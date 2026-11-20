"use strict";
((root, factory) => {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.RimeSession = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  function payload(token) {
    try {
      const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(part + "=".repeat((4 - part.length % 4) % 4)));
    } catch { return null; }
  }
  function createSession({storage, now = () => Date.now() / 1000, key = "rime.admin.session"} = {}) {
    let current = null, version = 0;
    const remove = () => { try { storage?.removeItem(key); } catch {} };
    const valid = value => {
      if (!value || typeof value.token !== "string" || value.token.length > 32768 || typeof value.username !== "string") return false;
      const data = payload(value.token);
      return !!data && (data.exp == null || typeof data.exp === "number" && Number.isFinite(data.exp) && data.exp > now());
    };
    try {
      const saved = JSON.parse(storage?.getItem(key) || "null");
      if (valid(saved)) { current = {token:saved.token, username:saved.username}; version++; }
      else remove();
    } catch { remove(); }
    return {
      get token() { return current?.token || null; },
      get username() { return current?.username || ""; },
      get version() { return version; },
      set(token, username) {
        const value = {token, username};
        if (!valid(value)) throw new Error("Сервер вернул некорректную или истёкшую сессию.");
        current = value; version++;
        try { storage?.setItem(key, JSON.stringify(value)); } catch {}
      },
      clear() { current = null; version++; remove(); },
      capture() { return {token:current?.token || null, version}; },
      matches(captured) { return captured.version === version && captured.token === (current?.token || null); }
    };
  }
  function sessionChanged() {
    const error = new Error("Запрос отменён после смены сессии.");
    error.name = "SessionChangedError";
    return error;
  }
  function createApi({session, fetch:send, onUnauthorized = () => {}, timeout = 20000}) {
    const pending = new Set();
    async function api(path, options = {}) {
      const captured = session.capture(), abort = new AbortController();
      let timedOut = false, rejectedAuth = false;
      const requestTimeout = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0 ? Math.min(options.timeoutMs, 180000) : timeout;
      const timer = setTimeout(() => { timedOut = true; abort.abort(); }, requestTimeout);
      const externalAbort = () => abort.abort();
      if (options.signal?.aborted) abort.abort();
      else options.signal?.addEventListener("abort", externalAbort, {once:true});
      pending.add(abort);
      try {
        const request = {...options}, headers = {...options.headers};
        if (captured.token) headers.Authorization = "Bearer " + captured.token;
        if (options.json) { headers["Content-Type"] = "application/json"; request.body = JSON.stringify(options.json); }
        delete request.json; delete request.raw; delete request.timeoutMs;
        const response = await send(path, {...request, headers, signal:abort.signal, credentials:"same-origin", cache:"no-store"});
        if (!session.matches(captured)) throw sessionChanged();
        if (!response.ok) {
          let detail;
          try { detail = (await response.json()).detail; } catch {}
          if (!session.matches(captured)) throw sessionChanged();
          if (response.status === 401 && captured.token) {
            rejectedAuth = true;
            session.clear(); onUnauthorized();
            const error = new Error("Сессия завершена. Войдите снова."); error.name = "UnauthorizedError"; throw error;
          }
          const error = new Error(typeof detail === "string" ? detail : `Запрос не выполнен (${response.status}). Повторите позже.`);
          error.status = response.status;
          throw error;
        }
        const value = options.raw ? response : response.status === 204 ? null : await response.json();
        if (!session.matches(captured)) throw sessionChanged();
        return value;
      } catch (error) {
        if (!rejectedAuth && !session.matches(captured)) throw sessionChanged();
        if (error.name === "AbortError") throw new Error(timedOut ? "Сервер не ответил вовремя. Сессия сохранена; данные не обновлены." : "Запрос отменён.");
        throw error;
      } finally {
        clearTimeout(timer); pending.delete(abort);
        options.signal?.removeEventListener("abort", externalAbort);
      }
    }
    api.abortAll = () => pending.forEach(controller => controller.abort());
    return api;
  }
  return {createSession, createApi};
});
