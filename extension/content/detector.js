/* global PYPHISH_MESSAGES */

const { MSG_TYPES, RISK_LEVELS, scoreForSensitivity } = PYPHISH_MESSAGES;

let tooltipEl;
let bannerEl;
let hideTimeout;
let currentHoverUrl = null;
let hoverTimer;
let settingsCache = null;
let settingsFetchedAt = 0;

async function getSettings() {
  const now = Date.now();
  if (!settingsCache || now - settingsFetchedAt > 10_000) {
    settingsCache = await browser.runtime.sendMessage({
      type: MSG_TYPES.FETCH_SETTINGS
    });
    settingsFetchedAt = now;
  }
  return settingsCache;
}

function ensureTooltip() {
  if (!tooltipEl) {
    tooltipEl = document.createElement("div");
    tooltipEl.className = "pyphish-tooltip hidden";
    document.documentElement.appendChild(tooltipEl);
  }
  return tooltipEl;
}

function ensureBanner() {
  if (!bannerEl) {
    bannerEl = document.createElement("div");
    bannerEl.className = "pyphish-banner hidden";
    const closeBtn = document.createElement("button");
    closeBtn.textContent = "×";
    closeBtn.className = "pyphish-close";
    closeBtn.addEventListener("click", () => bannerEl.classList.add("hidden"));

    const title = document.createElement("h4");
    title.className = "pyphish-title";

    const desc = document.createElement("p");
    desc.className = "pyphish-desc";

    bannerEl.appendChild(closeBtn);
    bannerEl.appendChild(title);
    bannerEl.appendChild(desc);
    document.documentElement.appendChild(bannerEl);
  }
  return bannerEl;
}

function riskClass(level) {
  switch (level) {
    case RISK_LEVELS.HIGH:
      return "danger";
    case RISK_LEVELS.MEDIUM:
      return "warning";
    default:
      return "safe";
  }
}

function showTooltip(x, y, result) {
  const el = ensureTooltip();
  el.className = `pyphish-tooltip ${riskClass(result.risk_level)}`;
  el.textContent = `${result.risk_level} (${result.risk_score}%)`;
  const offset = 12;
  el.style.left = `${x + offset}px`;
  el.style.top = `${y + offset}px`;
  el.classList.remove("hidden");
  clearTimeout(hideTimeout);
  hideTimeout = setTimeout(() => el.classList.add("hidden"), 4000);
}

function showBanner(result) {
  const el = ensureBanner();
  el.querySelector(".pyphish-title").textContent = result.is_phishing
    ? "Possível phishing detectado"
    : "Página suspeita";
  el.querySelector(".pyphish-desc").textContent = `${result.url}\nRisco: ${result.risk_level} (${result.risk_score}%)`;
  el.className = `pyphish-banner ${riskClass(result.risk_level)}`;
}

function handleMouseMove(event) {
  const link = event.target.closest("a[href], area[href]");
  if (!link) {
    currentHoverUrl = null;
    return;
  }
  const url = link.href;
  if (!url || !/^https?:/i.test(url)) {
    return;
  }
  if (currentHoverUrl === url) {
    return;
  }
  currentHoverUrl = url;
  if (hoverTimer) clearTimeout(hoverTimer);
  hoverTimer = setTimeout(async () => {
    try {
      const settings = await getSettings();
      if (!settings.hoverAnalysis) return;
      if (Array.isArray(settings.whitelist) && settings.whitelist.length) {
        const host = (() => {
          try {
            return new URL(url).hostname.replace(/^www\\./, \"\");
          } catch (err) {
            return url;
          }
        })();
        if (
          settings.whitelist.some((entry) => {
            const normalized = entry.trim().toLowerCase();
            if (!normalized) return false;
            if (normalized.startsWith(\"*\")) {
              return host.endsWith(normalized.slice(1));
            }
            return host === normalized.replace(/^www\\./, \"\");
          })
        ) {
          return;
        }
      }
      const result = await browser.runtime.sendMessage({
        type: MSG_TYPES.ANALYZE_LINK,
        payload: { url }
      });
      if (!result || result.skipped) return;
      const rect = link.getBoundingClientRect();
      const x = rect.left + window.scrollX;
      const y = rect.top + window.scrollY;
      showTooltip(x, y, result);
    } catch (err) {
      console.warn("PyPhish hover error", err);
    }
  }, 250);
}

document.addEventListener("mouseover", handleMouseMove, true);
document.addEventListener("focusin", handleMouseMove, true);
document.addEventListener(
  "mouseout",
  (event) => {
    const related = event.relatedTarget;
    if (!related || !event.currentTarget) return;
    if (!event.target.closest("a[href], area[href]") || (related && related.closest && related.closest("a[href], area[href]"))) {
      return;
    }
    if (tooltipEl) {
      tooltipEl.classList.add("hidden");
    }
  },
  true
);

browser.runtime.onMessage.addListener((message) => {
  const { type, payload } = message || {};
  if (type === MSG_TYPES.ANALYSIS_RESULT) {
    showBanner(payload);
  }
});
