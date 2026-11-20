"use strict";
(() => {
  let dialog, node, service, plan, draft, options, timer, revision = 0, formRevision=0;
  const key = value => "rime.proxy.delete." + value.id;
  const find = name => dialog.querySelector("#proxy-delete-" + name);
  const api = (...args) => window.Rime.api(...args);
  const text = (tag, value, className) => window.Rime.el(tag, value, className);

  function ensure() {
    if (dialog) return;
    dialog = document.createElement("dialog");
    dialog.className = "update-dialog";
    dialog.setAttribute("aria-labelledby", "proxy-delete-title");
    dialog.innerHTML = `<header class="update-heading"><div><p class="eyebrow">УПРАВЛЕНИЕ ПРОКСИ</p><h2 id="proxy-delete-title">Удалить прокси</h2></div><button id="proxy-delete-close" class="quiet" aria-label="Закрыть">×</button></header>
      <p id="proxy-delete-target"></p><p id="proxy-delete-route" class="muted"></p>
      <form id="proxy-delete-form"><div class="form-grid"><label>SSH-адрес<input name="host" autocomplete="off" required></label><label>SSH-порт<input name="ssh_port" type="number" min="1" max="65535" required></label><label>SSH-пользователь<input name="username" autocomplete="off" required></label><label>Способ входа<select name="method"><option value="password">Пароль</option><option value="key">SSH-ключ</option></select></label></div>
      <label id="proxy-delete-password-label">SSH-пароль<input name="password" type="password" autocomplete="off" required></label><label id="proxy-delete-key-label" hidden>Приватный SSH-ключ<textarea name="private_key" autocomplete="off" disabled></textarea></label><label id="proxy-delete-passphrase-label" hidden>Пароль SSH-ключа<input name="key_passphrase" type="password" autocomplete="off" disabled></label><button id="proxy-delete-check" class="secondary" type="submit">Проверить удаление</button></form>
      <section id="proxy-delete-trust" hidden><h3>Проверка подлинности сервера</h3><code id="proxy-delete-fingerprint"></code><label class="check"><input id="proxy-delete-trusted" type="checkbox"> Отпечаток сервера проверен</label><button id="proxy-delete-continue" class="secondary" disabled>Продолжить проверку</button></section>
      <section id="proxy-delete-plan" hidden><h3>Будут удалены</h3><ul id="proxy-delete-effects"></ul><button id="proxy-delete-confirm" class="primary danger">Удалить прокси</button></section>
      <section id="proxy-delete-job" hidden><div id="proxy-delete-progress"></div><p id="proxy-delete-message" role="status"></p><button id="proxy-delete-retry" class="secondary" hidden>Повторить проверку</button></section>
      <p id="proxy-delete-error" class="error" role="alert" hidden></p>`;
    document.body.append(dialog);
    find("close").addEventListener("click", () => dialog.close());
    dialog.addEventListener("close", () => { revision++; clearTimeout(timer); draft = null; find("form").reset(); });
    const form = find("form");
    const invalidate=()=>{
      formRevision++;plan=null;draft=null;
      find('trust').hidden=true;find('plan').hidden=true;
      find('trusted').checked=false;find('continue').disabled=true;find('check').disabled=false;
    };
    form.addEventListener('input',invalidate);
    form.elements.method.addEventListener("change", () => {
      invalidate();
      for(const field of ['password','private_key','key_passphrase'])form.elements[field].value='';
      const useKey = form.elements.method.value === "key";
      find("password-label").hidden = useKey;
      find("key-label").hidden = !useKey;
      find("passphrase-label").hidden = !useKey;
      form.elements.password.disabled = useKey;
      form.elements.password.required = !useKey;
      form.elements.private_key.disabled = !useKey;
      form.elements.private_key.required = useKey;
      form.elements.key_passphrase.disabled = !useKey;
    });
    form.addEventListener("submit", inspect);
    find("trusted").addEventListener("change", () => { find("continue").disabled = !find("trusted").checked; });
    find("continue").addEventListener("click", prepare);
    find("confirm").addEventListener("click", deploy);
    find("retry").addEventListener("click", () => open(node, {id: service.id}));
  }

  function error(message) {
    find("error").textContent = message || "";
    find("error").hidden = !message;
  }

  async function open(value, selected) {
    ensure(); revision++; clearTimeout(timer); node = value; service = selected; plan = null; draft = null;
    const owner=revision;
    error(""); find("form").reset(); find("form").hidden = false;
    find("form").elements.method.dispatchEvent(new Event("change"));
    for (const name of ["trust", "plan", "job"]) find(name).hidden = true;
    find("check").disabled = false;
    dialog.showModal();
    try {
      const received = await api("/api/fleet/proxy/" + encodeURIComponent(service.id) + "/delete/options");
      if(owner!==revision||!dialog.open)return;
      options=received;
      const form = find("form");
      for (const field of ["host", "ssh_port", "username"]) form.elements[field].value = options[field];
      find("target").textContent = node.name + " · " + [options.http_port && "HTTP " + options.http_port, options.https_port && "HTTPS " + options.https_port].filter(Boolean).join(" · ");
      find("route").textContent = options.via_entry ? "Доступ к серверу через " + options.entry_name : "Прямой SSH-доступ к серверу";
      form.elements.password.focus();
    } catch (failure) { if(owner===revision&&dialog.open)error(failure.message); }
  }

  async function inspect(event) {
    event.preventDefault(); error(""); find("check").disabled = true;
    const form = find("form"), values = Object.fromEntries(new FormData(form));
    const owner=revision,epoch=formRevision;
    draft = {host: values.host, ssh_port: Number(values.ssh_port), username: values.username,
      password: values.password || "", private_key: values.private_key || "", key_passphrase: values.key_passphrase || ""};
    try {
      const identity = await api("/api/fleet/provision/host-key", {method: "POST", json: {host: draft.host, ssh_port: draft.ssh_port}});
      if(owner!==revision||epoch!==formRevision||!dialog.open)return;
      draft.address = identity.address; draft.fingerprint = identity.fingerprint;
      if (identity.fingerprint === options.fingerprint) return await prepare();
      find("fingerprint").textContent = identity.fingerprint;
      find("trust").hidden = false;
      find("trusted").checked = false;
      find("continue").disabled = true;
    } catch (failure) { if(owner===revision&&epoch===formRevision&&dialog.open){error(failure.message); find("check").disabled = false;} }
  }

  async function prepare() {
    if(!draft)return;
    const owner=revision,epoch=formRevision;
    error(""); find("continue").disabled = true;
    try {
      const received = await api("/api/fleet/proxy/" + encodeURIComponent(service.id) + "/delete/plan", {method: "POST", json: draft, timeoutMs: 60000});
      if(owner!==revision||epoch!==formRevision||!dialog.open)return;
      plan=received;
      find("form").hidden = true; find("trust").hidden = true; find("plan").hidden = false;
      const items = Object.entries(plan.summary).filter(([, value]) => value != null && value !== 0).map(([name, value]) => text("li", name + " · " + value));
      find("effects").replaceChildren(...items); find("confirm").disabled = false;
    } catch (failure) { if(owner===revision&&epoch===formRevision&&dialog.open){error(failure.message); find("check").disabled = false; find("continue").disabled = false;} }
  }

  async function deploy() {
    if (!plan) return;
    const owner=revision,selectedNode=node,selectedService=service,selectedPlan=plan;
    const saved={id:selectedPlan.id,service:selectedService.id};
    try{sessionStorage.setItem(key(selectedNode),JSON.stringify(saved));}catch{}
    error(""); find("confirm").disabled = true;
    try {
      const job = await api("/api/fleet/proxy/delete/deploy", {method: "POST", json: {plan_id: selectedPlan.id}});
      if(owner!==revision||!dialog.open)return;
      draft = null; find("form").reset(); find("plan").hidden = true; find("job").hidden = false;
      poll(job.id, revision);
    } catch (failure) {
      try{
        await api('/api/fleet/proxy/jobs/'+encodeURIComponent(selectedPlan.id));
        if(owner===revision&&dialog.open){find('plan').hidden=true;find('job').hidden=false;poll(selectedPlan.id,revision);}
      }catch{
        try{if(JSON.parse(sessionStorage.getItem(key(selectedNode))||'null')?.id===selectedPlan.id)sessionStorage.removeItem(key(selectedNode));}catch{}
        if(owner===revision&&dialog.open){error(failure.message);find('confirm').disabled=false;}
      }
    }
  }

  async function poll(id, version) {
    clearTimeout(timer);
    try {
      const job = await api("/api/fleet/proxy/jobs/" + encodeURIComponent(id));
      if (version !== revision || !dialog.open) return;
      find("message").textContent = job.message;
      window.RimeProgress.mount(find("progress")).update(window.RimeProgress.job(job));
      const finished = ["succeeded", "failed", "rolled_back"].includes(job.state);
      find("retry").hidden = !finished || job.state === "succeeded";
      if (job.state === "succeeded") {
        try { sessionStorage.removeItem(key(node)); } catch {}
        document.dispatchEvent(new CustomEvent("rime:proxy-deleted", {detail: {node: node.id}}));
      }
      if (!finished) timer = setTimeout(() => poll(id, version), 1500);
    } catch (failure) {
      if(version!==revision||!dialog.open)return;
      error(failure.message);
      if(failure.status===404){try{sessionStorage.removeItem(key(node));}catch{}find('retry').hidden=false;return;}
      timer = setTimeout(() => poll(id, version), 3000);
    }
  }

  async function resume(value, saved) {
    ensure(); revision++; node = value; service = {id: saved.service};
    find("form").hidden = true; find("plan").hidden = true; find("trust").hidden = true; find("job").hidden = false;
    error(""); dialog.showModal(); poll(saved.id, revision);
  }

  function pending(value) {
    try { return JSON.parse(sessionStorage.getItem(key(value)) || "null"); } catch { return null; }
  }
  window.RimeProxyDelete = {open, resume, pending};
})();
