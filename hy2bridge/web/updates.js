"use strict";
(() => {
  const button = document.getElementById("rime-version");
  if (!button || !window.Rime) return;
  const {api, el} = window.Rime;
  const dialog = document.createElement("dialog");
  dialog.className = "update-dialog";
  dialog.setAttribute("aria-labelledby", "update-title");
  dialog.innerHTML = `<form method="dialog" class="update-heading"><div><p class="eyebrow">ПРИЛОЖЕНИЕ</p><h2 id="update-title">Обновление Rime</h2></div><button class="quiet" aria-label="Закрыть обновления">×</button></form>
    <div class="update-versions"><div><span>Установлена</span><strong id="update-current">—</strong></div><span class="update-arrow" aria-hidden="true">→</span><div><span>Новая версия</span><strong id="update-latest">—</strong></div></div>
    <p id="update-summary" role="status">Получение версии…</p>
    <section id="update-notes-section" hidden><h3>Что изменилось</h3><pre id="update-notes"></pre></section>
    <section id="update-progress-section" hidden aria-label="Ход обновления"><ol id="update-steps"></ol><progress id="update-download" max="100" hidden></progress><p id="update-progress" role="status"></p></section>
    <p id="update-error" class="error" role="alert" hidden></p>
    <section id="update-rollback" class="update-rollback" hidden><h3>Предыдущая версия</h3><p id="update-rollback-text" class="muted"></p>
      <div id="update-rollback-confirm" class="update-confirm" hidden><p>Панель перезапустится на версии <b id="update-rollback-target"></b>. Пользователи, подписки и настройки сохранятся: база остаётся текущей, откат возможен только при той же схеме базы. При сбое запуска вернётся текущая версия.</p>
        <div class="update-actions"><button id="update-rollback-cancel" type="button" class="secondary">Не откатывать</button><button id="update-rollback-run" type="button" class="secondary danger">Подтвердить откат</button></div></div>
      <div class="update-actions"><button id="update-rollback-start" type="button" class="secondary"></button></div></section>
    <p id="update-agent-help" class="muted" hidden>Подключите службу обновления на сервере панели. Инструкция находится в разделе «Документация».</p>
    <div class="update-actions"><button id="update-cancel" type="button" class="secondary danger" hidden>Остановить обновление</button><button id="update-check" type="button" class="secondary">Проверить GitHub</button><button id="update-install" type="button" class="primary" hidden>Создать резерв и обновить</button></div>`;
  document.body.append(dialog);
  const find = id => dialog.querySelector("#" + id);
  const running = new Set(["queued", "checking", "downloading", "backup", "installing", "verifying", "rollback"]);
  const phases = [
    ["downloading", "Загрузка релиза"], ["backup", "Резервная копия"],
    ["installing", "Установка"], ["verifying", "Проверка панели"]
  ];
  const errors = {
    release_unavailable: "GitHub сейчас недоступен. Повторите проверку позже.",
    release_not_ready: "Файлы релиза ещё готовятся. Повторите проверку позже.",
    invalid_release_manifest: "Не удалось проверить комплект релиза.",
    release_checksum_mismatch: "Контрольная сумма файла релиза не совпала.",
    release_signature_invalid: "Подпись релиза не прошла проверку. Обновление остановлено.",
    image_identity_mismatch: "Образ не соответствует выбранному релизу.",
    release_changed: "Релиз изменился после проверки. Проверьте обновления заново.",
    unsupported_architecture: "Для этой архитектуры сервера ещё нет готового обновления.",
    agent_unavailable: "Служба обновления не подтвердила запрос. Проверьте её состояние на сервере панели.",
    node_operation_running: "Дождитесь завершения установки или переноса ноды.",
    insufficient_disk_space: "На сервере недостаточно места для загрузки и резервной копии.",
    update_running: "Обновление уже выполняется.",
    panel_not_running: "Контейнер панели остановлен. Проверьте службу обновления на хосте.",
    unsupported_database: "Обновление требует SQLite на постоянном диске.",
    downgrade_requires_preparation: "Откат требует подготовки счётчиков и совместимого контроллера по инструкции.",
    rollback_schema_incompatible: "Схема базы изменилась. Автоматический переход на прежнюю версию остановлен.",
    rollback_not_current: "Этот резерв относится к другой установленной версии.",
    rollback_not_available: "Выбранная версия для отката недоступна.",
    candidate_failed: "Проверка новой версии завершилась ошибкой. Восстановлена предыдущая версия.",
    version_not_newer: "Эта версия уже установлена.",
    source_mount_overrides_image: "Установка использует примонтированные исходники. Обновите способ развёртывания по инструкции.",
    request_expired: "Запрос устарел. Проверьте обновления и повторите установку.",
    rollback_retry: "Служба ожидает доступности Docker для завершения восстановления.",
    update_failed: "Обновление остановлено. Подробности сохранены на сервере панели.",
    update_cancelled: "Обновление остановлено по запросу. Панель не изменялась.",
    update_not_cancellable: "Остановить можно только до начала резервного копирования. Дальше при сбое сработает автоматический откат.",
    rollback_not_available: "Откат недоступен: предыдущий образ удалён или установлена другая версия.",
    rollback_confirmation_required: "Подтвердите откат."
  };
  let status = null, timer = null, busy = false;

  function showError(error) {
    const code = typeof error === "string" ? error : error.message;
    find("update-error").textContent = errors[code] || "Не удалось выполнить запрос. Повторите попытку.";
    find("update-error").hidden = false;
  }

  function render(value) {
    status = value;
    const job = value.job || {}, active = running.has(job.phase), rollback = job.operation === "rollback";
    document.getElementById("rime-current-version").textContent = value.current_version;
    find("update-current").textContent = value.current_version;
    find("update-title").textContent = value.demo ? "Обновление Rime · демо" : "Обновление Rime";
    find("update-latest").textContent = value.latest?.version || "—";
    find("update-check").disabled = active || busy;
    find("update-install").hidden = !value.available || active;
    find("update-install").disabled = !value.enabled || busy;
    find("update-agent-help").hidden = value.enabled || active;
    find("update-notes-section").hidden = !value.latest?.notes;
    find("update-notes").textContent = value.latest?.notes || "";
    let message = value.available ? "Доступна новая версия. Перед установкой будет создана резервная копия." :
      value.checked_at ? (value.latest ? "Установлена актуальная версия." : "Опубликованных обновлений Rime пока нет.") : "Проверьте опубликованные релизы на GitHub.";
    if (job.phase === "succeeded") message = rollback ? `Откат на ${job.version} выполнен. Можно продолжать работу.` : `Обновление до ${job.version} установлено. Можно продолжать работу.`;
    if (job.phase === "rolled_back") message = "Восстановлена предыдущая версия. Подробности сохранены на сервере панели.";
    if (active) message = (rollback ? "Откат выполняется." : "Обновление выполняется.") + " Статус сохранится при закрытии этого окна.";
    if (active && value.cancel_requested) message = "Остановка запрошена. Служба обновления завершит загрузку и ничего не изменит.";
    find("update-summary").textContent = message;
    find("update-progress-section").hidden = !job.phase;
    const shown = rollback ? phases.filter(([phase]) => phase !== "downloading") : phases;
    const index = shown.findIndex(([phase]) => phase === job.phase);
    const steps = shown.map(([phase, label], step) => {
      const item = el("li", label);
      item.className = job.phase === "succeeded" || step < index ? "done" : step === index ? "current" : "";
      if (step === index) item.setAttribute("aria-current", "step");
      return item;
    });
    find("update-steps").replaceChildren(...steps);
    const progress = find("update-download");
    progress.hidden = job.phase !== "downloading";
    progress.value = job.progress || 0;
    find("update-progress").textContent = {
      queued: "Ожидание службы обновления…", checking: "Проверка релиза…",
      downloading: `Загружено ${job.progress || 0}%` + (job.retries ? ` · связь с GitHub прерывалась, загрузка продолжена (${job.retries})` : ""),
      backup: "Сохранение базы и конфигурации…", installing: "Панель перезапускается…", verifying: "Проверка запуска новой версии…", rollback: "Восстановление предыдущей версии…"
    }[job.phase] || "";
    const cancel = find("update-cancel");
    cancel.hidden = !value.cancellable;
    cancel.disabled = busy;
    const offer = value.rollback;
    find("update-rollback").hidden = !offer || active;
    if (offer) {
      const older = compareVersions(offer.version, value.current_version) < 0;
      find("update-rollback-text").textContent = older ?
        `Можно вернуться на версию ${offer.version}, которая работала до последнего обновления.` :
        `Можно вернуть версию ${offer.version}, которая работала до последнего отката.`;
      find("update-rollback-start").textContent = older ? `Откатить на ${offer.version}` : `Вернуть ${offer.version}`;
      find("update-rollback-target").textContent = offer.version;
    }
    if (!offer || active) find("update-rollback-confirm").hidden = true;
    find("update-rollback-start").hidden = !find("update-rollback-confirm").hidden;
    find("update-rollback-start").disabled = busy;
    if (job.error) showError(job.error);
    else find("update-error").hidden = true;
    clearTimeout(timer);
    if (active && dialog.open) timer = setTimeout(load, 2000);
  }

  async function load() {
    try {
      render(await api("/api/system/updates"));
    } catch (error) {
      const phase = status?.job?.phase;
      if (running.has(phase)) {
        // Only installation restarts the panel; earlier phases run on the host while the panel keeps serving.
        find("update-progress").textContent = ["installing", "verifying", "rollback"].includes(phase) ?
          "Ожидание панели после перезапуска…" :
          "Нет ответа от панели. Обновление продолжается на сервере, запрос повторяется…";
        if (dialog.open) timer = setTimeout(load, 2500);
      } else showError(error);
    }
  }

  button.addEventListener("click", () => { dialog.showModal(); load(); });
  document.getElementById('rime-version-mobile')?.addEventListener('click',()=>{dialog.showModal();load();});
  dialog.addEventListener("close", () => clearTimeout(timer));
  find("update-check").addEventListener("click", async () => {
    busy = true;
    find("update-check").disabled = true;
    find("update-error").hidden = true;
    find("update-summary").textContent = "Проверка релизов на GitHub…";
    try { render(await api("/api/system/updates/check", {method: "POST",timeoutMs:60000})); }
    catch (error) { showError(error); }
    finally {
      busy = false;
      find("update-check").disabled = running.has(status?.job?.phase);
      find("update-install").disabled = !status?.enabled || running.has(status?.job?.phase);
    }
  });
  find("update-install").addEventListener("click", async () => {
    if (!status?.available || busy) return;
    busy = true;
    find("update-install").disabled = true;
    find("update-error").hidden = true;
    try { render(await api("/api/system/updates", {method: "POST", json: {version: status.latest.version},timeoutMs:60000})); }
    catch (error) { showError(error); }
    finally {
      busy = false;
      find("update-install").disabled = !status?.enabled || running.has(status?.job?.phase);
    }
  });
  function compareVersions(left, right) {
    const parts = value => String(value).split(/[.-]/).map(part => Number.parseInt(part, 10) || 0);
    const a = parts(left), b = parts(right);
    for (let i = 0; i < Math.max(a.length, b.length); i++) if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) - (b[i] || 0);
    return 0;
  }

  async function act(path, payload) {
    busy = true;
    find("update-error").hidden = true;
    try { render(await api(path, {method: "POST", ...(payload ? {json: payload} : {}), timeoutMs: 60000})); }
    catch (error) { showError(error); }
    finally { busy = false; if (status) render(status); }
  }

  find("update-cancel").addEventListener("click", () => act("/api/system/updates/cancel"));
  find("update-rollback-start").addEventListener("click", () => {
    find("update-rollback-confirm").hidden = false;
    find("update-rollback-start").hidden = true;
    find("update-rollback-run").focus();
  });
  find("update-rollback-cancel").addEventListener("click", () => {
    find("update-rollback-confirm").hidden = true;
    find("update-rollback-start").hidden = false;
  });
  find("update-rollback-run").addEventListener("click", () => {
    find("update-rollback-confirm").hidden = true;
    act("/api/system/updates/rollback", {confirmation: "rollback"});
  });
  document.addEventListener("rime:session-ready",load);
  if(window.Rime?.state.token)load();
})();
