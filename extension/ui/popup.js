/* global PYPHISH_MESSAGES */

const { MSG_TYPES, RISK_LEVELS } = PYPHISH_MESSAGES;

let settings = null;
let activeTabId = null;

function statusClass(level) {
  switch (level) {
    case RISK_LEVELS.HIGH:
      return "danger";
    case RISK_LEVELS.MEDIUM:
      return "warning";
    case RISK_LEVELS.LOW:
      return "safe";
    default:
      return "";
  }
}

function renderStatus(result) {
  const section = document.getElementById("statusSection");
  const levelEl = document.getElementById("statusLevel");
  const urlEl = document.getElementById("statusUrl");
  const summaryEl = document.getElementById("statusSummary");

  if (!result) {
    section.className = "status";
    levelEl.textContent = "--";
    urlEl.textContent = "Sem dados";
    summaryEl.textContent = "";
    return;
  }

  section.className = `status ${statusClass(result.risk_level)}`;
  levelEl.textContent = `${result.risk_level} (${result.risk_score || 0}%)`;
  urlEl.textContent = result.url || "--";
  const summary = Array.isArray(result.summary) && result.summary.length
    ? result.summary.slice(0, 2).join("; ")
    : "Sem características suspeitas";
  summaryEl.textContent = summary;
}

async function loadSettings() {
  settings = await browser.runtime.sendMessage({ type: MSG_TYPES.FETCH_SETTINGS });
  document.getElementById("autoBlockToggle").checked = !!settings.autoBlock;
  document.getElementById("notificationsToggle").checked = !!settings.notifications;
  document.getElementById("hoverToggle").checked = !!settings.hoverAnalysis;
}

async function loadActiveTabAnalysis() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  activeTabId = tab.id;
  const result = await browser.runtime.sendMessage({
    type: MSG_TYPES.ANALYZE_TAB,
    payload: { tabId: tab.id }
  });
  renderStatus(result);
}

async function saveSetting(partial) {
  settings = { ...settings, ...partial };
  await browser.runtime.sendMessage({
    type: MSG_TYPES.SETTINGS_UPDATED,
    payload: { settings }
  });
}

document.getElementById("autoBlockToggle").addEventListener("change", (ev) => {
  saveSetting({ autoBlock: ev.target.checked });
});

document.getElementById("notificationsToggle").addEventListener("change", (ev) => {
  saveSetting({ notifications: ev.target.checked });
});

document.getElementById("hoverToggle").addEventListener("change", (ev) => {
  saveSetting({ hoverAnalysis: ev.target.checked });
});

document.getElementById("openOptions").addEventListener("click", () => {
  browser.runtime.openOptionsPage();
});

document.getElementById("manualForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const url = ev.target.manualInput.value.trim();
  if (!url) return;
  renderStatus({ url, risk_level: "AGUARDANDO", risk_score: 0, summary: ["Analisando..."] });
  const result = await browser.runtime.sendMessage({
    type: MSG_TYPES.ANALYZE_LINK,
    payload: { url }
  });
  renderStatus(result);
});

(async function init() {
  await loadSettings();
  await loadActiveTabAnalysis();
})();
