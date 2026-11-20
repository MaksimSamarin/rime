"use strict";
((root, factory) => {
  const value = factory();
  if (typeof module === "object" && module.exports) module.exports = value;
  else root.RimeProgress = value;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  const stages = [
    [/проверка доступа|предварительн|проверка сервера|проверка ssh/i, "Проверка доступа"],
    [/установка python|подготовка сервера|резервирован|сохранение конфигурац/i, "Подготовка"],
    [/передача|загрузка.*образ|загрузка.*сборк/i, "Передача файлов"],
    [/запуск|переключение|удаление.*контейнер|остановка/i, "Применение"],
    [/сборщик|ожидание.*метрик|ожидание.*cpu/i, "Получение состояния"],
    [/проверка.*трафик|проверка авторизац|проверка.*tls|проверка результата/i, "Проверка результата"],
    [/публикац|обновление.*реестр|регистрац|фиксац/i, "Сохранение результата"]
  ];
  function job(job) {
    if (job.context?.operation === "route-switch") {
      const progress = job.context.progress || {};
      const total = Number.isInteger(progress.total) && progress.total > 0 ? progress.total : 7;
      if (job.state === "succeeded") {
        return {value:total,total,label:"Новый вход работает",state:"done"};
      }
      const terminal = ["failed","rolled_back"].includes(job.state);
      const completed = Number.isInteger(progress.completed) && progress.completed >= 0 ?
        Math.min(progress.completed,total - 1) : null;
      return {value:completed,total,
        label:job.state === "rolled_back" ? "Сохранён предыдущий маршрут" :
          typeof progress.label === "string" && progress.label ? progress.label : "Смена входного сервера",
        state:terminal ? "failed" : "running"};
    }
    const selected = job.context?.operation === "delete" ? [
      [/проверка доступа/i,"Проверка доступа"],
      [/сохранение|остановка/i,"Резерв и остановка"],
      [/удаление/i,"Удаление службы и правил"],
      [/проверка результата|результат сохранён/i,"Проверка результата"]
    ] : stages;
    const terminal = ["succeeded", "failed", "rolled_back"].includes(job.state);
    if (job.state === "succeeded") return {value: selected.length, total: selected.length, label: "Проверка завершена", state: "done"};
    if (job.state === "rolled_back") return {value: null, total: selected.length, label: "Восстановлена предыдущая конфигурация", state: "failed"};
    let index = -1;
    for (const step of job.steps || []) {
      const found = selected.findIndex(([pattern]) => pattern.test(typeof step === "string" ? step : step.message || ""));
      if (found !== -1) index = found;
    }
    return {value: index < 0 ? null : index, total: selected.length,
      label: index < 0 ? "Операция выполняется" : selected[index][1], state: terminal ? "failed" : "running"};
  }
  function mount(target) {
    if (!target || typeof document === "undefined") return {update() {}};
    let caption = target.querySelector(".process-caption"), bar = target.querySelector("progress");
    if (!caption) {
      target.classList.add("process-progress");
      caption = document.createElement("div"); caption.className = "process-caption";
      caption.setAttribute("role", "status");
      bar = document.createElement("progress"); bar.setAttribute("aria-label", "Ход операции");
      target.append(caption, bar);
    }
    return {update(value) {
      target.dataset.state = value.state || "running";
      bar.max = value.total || stages.length;
      if (value.value == null) bar.removeAttribute("value");
      else bar.value = value.value;
      const step = value.value == null || value.state === "done" ? "" : ` · этап ${value.value + 1} из ${bar.max}`;
      caption.textContent = value.label + step;
      target.setAttribute("aria-busy", String(value.state === "running"));
    }};
  }
  let activityCount = 0, activityRevision = 0;
  function activity(path, method = "GET") {
    if (typeof document === "undefined" || !["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase())) return () => {};
    let target = document.getElementById("operation-status");
    if (!target) {
      target = document.createElement("div"); target.id = "operation-status"; target.className = "operation-status";
      target.hidden = true; document.body.append(target);
    }
    const host=Array.from(document.querySelectorAll('dialog[open]')).at(-1)||document.body;
    if(target.parentElement!==host)host.append(target);
    target.classList.toggle('operation-inline',host!==document.body);
    const label = /delete|DELETE/.test(path + method) ? "Удаление и проверка результата" :
      /check|preflight|plan|host-key/.test(path) ? "Проверка сервера и настроек" :
      /deploy/.test(path) ? "Запуск развёртывания" : "Применение изменений";
    activityCount++; const revision = ++activityRevision;
    const delay = setTimeout(() => { target.hidden = false; mount(target).update({value:null,label,total:1,state:"running"}); }, 300);
    let completed = false;
    return successful => {
      if (completed) return; completed = true; clearTimeout(delay); activityCount--;
      if (activityCount) return;
      const finishedRevision = ++activityRevision;
      clearTimeout(delay);
      if (!target.hidden) mount(target).update({value:successful ? 1 : null,total:1,
        label:successful ? "Готово" : "Операция не завершена",state:successful ? "done" : "failed"});
      setTimeout(() => { if (!activityCount && finishedRevision === activityRevision) target.hidden = true; }, 1800);
    };
  }
  return {job, mount, activity};
});
