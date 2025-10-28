/* global PYPHISH_MESSAGES */

const { MSG_TYPES } = PYPHISH_MESSAGES;

let settings = null;

async function fetchSettings() {
  settings = await browser.runtime.sendMessage({ type: MSG_TYPES.FETCH_SETTINGS });
  applyToForm();
}

function applyToForm() {
  if (!settings) return;
  const form = document.getElementById("settingsForm");
  form.querySelectorAll('input[name="sensitivity"]').forEach((input) => {
    input.checked = input.value === settings.sensitivity;
  });
  document.getElementById("optAutoBlock").checked = !!settings.autoBlock;
  document.getElementById("optNotifications").checked = !!settings.notifications;
  document.getElementById("optHover").checked = !!settings.hoverAnalysis;
  document.getElementById("optWhitelist").value = (settings.whitelist || []).join("\n");
  document.getElementById("optApiBase").value = settings.apiBase || "";
}

async function saveSettings(event) {
  event.preventDefault();
  const form = event.target;
  const sensitivity = form.querySelector('input[name="sensitivity"]:checked')?.value || "medium";
  const autoBlock = form.optAutoBlock.checked;
  const notifications = form.optNotifications.checked;
  const hoverAnalysis = form.optHover.checked;
  const whitelist = form.optWhitelist.value
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
  const apiBase = form.optApiBase.value.trim() || settings.apiBase;

  settings = {
    ...settings,
    sensitivity,
    autoBlock,
    notifications,
    hoverAnalysis,
    whitelist,
    apiBase
  };

  await browser.runtime.sendMessage({
    type: MSG_TYPES.SETTINGS_UPDATED,
    payload: { settings }
  });

  const status = document.getElementById("saveStatus");
  status.textContent = "Salvo";
  setTimeout(() => (status.textContent = ""), 2000);
}

document.getElementById("settingsForm").addEventListener("submit", saveSettings);

fetchSettings();
