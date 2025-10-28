/* global PYPHISH_MESSAGES */

const { MSG_TYPES } = PYPHISH_MESSAGES;

const params = new URLSearchParams(window.location.search);
const targetUrl = decodeURIComponent(params.get("url") || "");
const targetScore = params.get("score") || "?";

document.getElementById("warnUrl").textContent = targetUrl;
document.getElementById("warnScore").textContent = `Risco estimado: ${targetScore}%`;

async function loadDetails() {
  const result = await browser.runtime.sendMessage({
    type: MSG_TYPES.RESULT_BY_URL,
    payload: { url: targetUrl }
  });
  const list = document.getElementById("warnReasons");
  list.innerHTML = "";
  if (result && Array.isArray(result.summary) && result.summary.length) {
    result.summary.forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      list.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.textContent = "Não foi possível recuperar detalhes adicionais.";
    list.appendChild(li);
  }
}

async function addToWhitelist() {
  const settings = await browser.runtime.sendMessage({ type: MSG_TYPES.FETCH_SETTINGS });
  const host = (() => {
    try {
      return new URL(targetUrl).hostname;
    } catch (err) {
      return targetUrl;
    }
  })();
  if (!settings.whitelist.includes(host)) {
    settings.whitelist = [...settings.whitelist, host];
    await browser.runtime.sendMessage({
      type: MSG_TYPES.SETTINGS_UPDATED,
      payload: { settings }
    });
  }
}

document.getElementById("btnBack").addEventListener("click", () => {
  browser.tabs.getCurrent().then((tab) => {
    if (tab && typeof tab.id === "number") {
      browser.tabs.remove(tab.id);
    } else {
      window.close();
    }
  });
});

document.getElementById("btnProceed").addEventListener("click", async () => {
  await addToWhitelist();
  const tab = await browser.tabs.getCurrent();
  if (tab && typeof tab.id === "number") {
    browser.tabs.update(tab.id, { url: targetUrl });
  } else {
    window.location.href = targetUrl;
  }
});

loadDetails();
