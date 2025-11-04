/* global PYPHISH_CONSTANTS, PYPHISH_MESSAGES, PYPHISH_STATE, PYPHISH_API */

const { BADGE_COLORS, CACHE_TTL_MS, RISK_THRESHOLDS } = PYPHISH_CONSTANTS;

const { MSG_TYPES, isDangerous, scoreForSensitivity } = PYPHISH_MESSAGES;

const tabResults = new Map();

async function evaluateUrl(url, settings) {
  const cached = PYPHISH_STATE.getCachedResult(url);
  if (cached) {
    return { result: cached, cached: true };
  }
  const analysis = await PYPHISH_API.analyzeUrl(url, settings.apiBase);
  PYPHISH_STATE.cacheResult(url, analysis, CACHE_TTL_MS);
  return { result: analysis, cached: false };
}

function badgeColorFor(result, threshold) {
  if (!result || result.error) {
    return BADGE_COLORS.warning;
  }
  if (isDangerous(result.risk_score, threshold)) {
    return BADGE_COLORS.danger;
  }
  if (result.risk_level === PYPHISH_MESSAGES.RISK_LEVELS.MEDIUM) {
    return BADGE_COLORS.warning;
  }
  return BADGE_COLORS.safe;
}

async function updateBadge(tabId, result, threshold) {
  if (tabId < 0) return;
  const color = badgeColorFor(result, threshold);
  const text =
    result && typeof result.risk_score === "number"
      ? `${Math.min(99, Math.max(0, Math.round(result.risk_score)))}`
      : "--";
  await browser.browserAction.setBadgeBackgroundColor({ tabId, color });
  await browser.browserAction.setBadgeText({ tabId, text });
}

async function notify(result, settings) {
  // Don't notify if notifications are disabled
  if (!settings.notifications) return;

  // Never notify for LOW risk sites (BAIXO) - only MEDIUM (MÉDIO) and HIGH (ALTO)
  if (result.risk_level === PYPHISH_MESSAGES.RISK_LEVELS.LOW) return;

  // Check if risk score exceeds the user's sensitivity threshold
  const threshold = scoreForSensitivity(settings.sensitivity, RISK_THRESHOLDS);
  if (!isDangerous(result.risk_score, threshold)) return;

  // Show notification for medium/high risk sites
  const title = result.is_phishing
    ? "ALERTA: phishing detectado"
    : "Página suspeita";
  const message = `${result.url}\nRisco: ${result.risk_level} (${result.risk_score}%)`;
  try {
    await browser.notifications.create({
      type: "basic",
      iconUrl: "assets/icon-48.png",
      title,
      message,
    });
  } catch (err) {
    console.warn("Notification error", err);
  }
}

async function handleAnalysisOutcome(details, result, settings) {
  const threshold = scoreForSensitivity(settings.sensitivity, RISK_THRESHOLDS);
  tabResults.set(details.tabId, result);
  await updateBadge(details.tabId, result, threshold);
  await notify(result, settings);

  const dangerous = isDangerous(result.risk_score, threshold);
  if (dangerous && settings.autoBlock && details.tabId >= 0) {
    const warningUrl = browser.runtime.getURL(
      `ui/warning.html?url=${encodeURIComponent(result.url)}&score=${result.risk_score}`,
    );
    browser.tabs.update(details.tabId, { url: warningUrl }).catch(() => {});
    return { cancel: true };
  }

  browser.tabs
    .sendMessage(details.tabId, {
      type: MSG_TYPES.ANALYSIS_RESULT,
      payload: result,
    })
    .catch(() => {});

  return {};
}

browser.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.type !== "main_frame" || details.method !== "GET") {
      return {};
    }
    if (!/^https?:/i.test(details.url)) {
      return {};
    }
    const settings = await PYPHISH_STATE.getSettings();
    if (PYPHISH_STATE.isWhitelisted(details.url, settings.whitelist)) {
      return {};
    }
    const { result } = await evaluateUrl(details.url, settings);
    return handleAnalysisOutcome(details, result, settings);
  },
  { urls: ["<all_urls>"] },
  ["blocking"],
);

browser.runtime.onMessage.addListener((message, sender) => {
  const { type, payload } = message || {};
  switch (type) {
    case MSG_TYPES.ANALYZE_LINK:
      return (async () => {
        const settings = await PYPHISH_STATE.getSettings();
        if (PYPHISH_STATE.isWhitelisted(payload.url, settings.whitelist)) {
          return { skipped: true };
        }
        const { result } = await evaluateUrl(payload.url, settings);
        return result;
      })();
    case MSG_TYPES.ANALYZE_TAB:
      return (async () => {
        const tabId = payload && payload.tabId;
        const settings = await PYPHISH_STATE.getSettings();
        const threshold = scoreForSensitivity(
          settings.sensitivity,
          RISK_THRESHOLDS,
        );
        if (tabResults.has(tabId)) {
          return tabResults.get(tabId);
        }
        const tab = await browser.tabs.get(tabId);
        if (tab.url.startsWith("moz-extension://")) {
          return null;
        }
        const { result } = await evaluateUrl(tab.url, settings);
        await updateBadge(tabId, result, threshold);
        return result;
      })();
    case MSG_TYPES.RESULT_BY_URL:
      return (async () => {
        const url = payload && payload.url;
        if (!url) return null;
        const cached = PYPHISH_STATE.getCachedResult(url);
        if (cached) return cached;
        const settings = await PYPHISH_STATE.getSettings();
        const { result } = await evaluateUrl(url, settings);
        return result;
      })();
    case MSG_TYPES.FETCH_SETTINGS:
      return PYPHISH_STATE.getSettings();
    case MSG_TYPES.SETTINGS_UPDATED:
      return (async () => {
        const next = await PYPHISH_STATE.saveSettings(payload.settings);
        PYPHISH_STATE.clearCache();
        tabResults.clear();
        return next;
      })();
    default:
      return undefined;
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});

browser.runtime.onInstalled.addListener(async () => {
  await browser.browserAction.setBadgeBackgroundColor({
    color: BADGE_COLORS.neutral,
  });
  await browser.browserAction.setBadgeText({ text: "" });
  // Ensure defaults exist
  await PYPHISH_STATE.saveSettings(await PYPHISH_STATE.getSettings());
});

browser.tabs.onActivated.addListener(async ({ tabId }) => {
  const settings = await PYPHISH_STATE.getSettings();
  const threshold = scoreForSensitivity(settings.sensitivity, RISK_THRESHOLDS);
  if (tabResults.has(tabId)) {
    await updateBadge(tabId, tabResults.get(tabId), threshold);
  } else {
    await browser.browserAction.setBadgeBackgroundColor({
      tabId,
      color: BADGE_COLORS.neutral,
    });
    await browser.browserAction.setBadgeText({ tabId, text: "" });
  }
});
