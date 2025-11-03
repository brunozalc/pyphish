/* global PYPHISH_MESSAGES */

const { MSG_TYPES, RISK_LEVELS } = PYPHISH_MESSAGES;

let tooltipEl;
let bannerEl;
let hideTimeout;
let currentHoverUrl = null;
let hoverTimer;
let settingsCache = null;
let settingsFetchedAt = 0;
let extensionLoaded = false;

function coerceElement(target) {
  if (!target) return null;
  if (target instanceof Element) return target;
  if (typeof Node !== "undefined" && target.nodeType === Node.TEXT_NODE) {
    return target.parentElement;
  }
  return null;
}

function findLinkFromTarget(target) {
  const element = coerceElement(target);
  if (!element) return null;

  // First try to find the closest link
  let link = element.closest("a[href], area[href]");

  // If not found and element itself is a link, use it
  if (!link && element.tagName === "A" && element.href) {
    link = element;
  }

  // For complex structures (like Google Search), check parent elements more thoroughly
  if (!link) {
    let current = element;
    let depth = 0;
    while (current && depth < 5) {
      if (current.tagName === "A" && current.href) {
        link = current;
        break;
      }
      current = current.parentElement;
      depth++;
    }
  }

  return link;
}

async function getSettings() {
  const now = Date.now();
  if (!settingsCache || now - settingsFetchedAt > 10_000) {
    settingsCache = await browser.runtime.sendMessage({
      type: MSG_TYPES.FETCH_SETTINGS,
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
  el.querySelector(".pyphish-desc").textContent =
    `${result.url}\nRisco: ${result.risk_level} (${result.risk_score}%)`;
  el.className = `pyphish-banner ${riskClass(result.risk_level)}`;
}

function handleMouseMove(event) {
  const link = findLinkFromTarget(event.target);
  if (!link) {
    currentHoverUrl = null;
    if (hoverTimer) {
      clearTimeout(hoverTimer);
      hoverTimer = null;
    }
    return;
  }

  // Get the actual URL - handle both href property and attribute
  let url = link.href || link.getAttribute("href");

  // Extract actual URL from Google's redirect format
  // Google uses: /url?q=https://actual-url.com&sa=...
  if (url && url.includes("/url?q=")) {
    try {
      const urlObj = new URL(url, window.location.href);
      const actualUrl = urlObj.searchParams.get("q");
      if (actualUrl) {
        console.log("PyPhish: Extracted from Google redirect:", actualUrl);
        url = actualUrl;
      }
    } catch (e) {
      // If parsing fails, use original URL
    }
  }

  if (!url || !/^https?:/i.test(url)) {
    // Don't log every single non-HTTP hover to reduce noise
    if (url && url.length > 0) {
      console.log("PyPhish: Skipping non-HTTP link:", url.substring(0, 50));
    }
    return;
  }

  console.log("PyPhish: Detected link hover:", url);
  currentHoverUrl = url;
  if (hoverTimer) clearTimeout(hoverTimer);
  hoverTimer = setTimeout(async () => {
    hoverTimer = null;
    if (currentHoverUrl !== url) return;
    try {
      console.log("PyPhish: Analyzing link after 250ms delay:", url);
      const settings = await getSettings();
      console.log(
        "PyPhish: Settings loaded, hoverAnalysis:",
        settings.hoverAnalysis,
      );
      if (!settings.hoverAnalysis) {
        console.log("PyPhish: Hover analysis disabled in settings");
        return;
      }
      if (Array.isArray(settings.whitelist) && settings.whitelist.length) {
        const host = (() => {
          try {
            return new URL(url).hostname.replace(/^www\./, "");
          } catch (err) {
            return url;
          }
        })();
        if (
          settings.whitelist.some((entry) => {
            const normalized = entry.trim().toLowerCase();
            if (!normalized) return false;
            if (normalized.startsWith("*")) {
              return host.endsWith(normalized.slice(1));
            }
            return host === normalized.replace(/^www\./, "");
          })
        ) {
          console.log("PyPhish: URL in whitelist, skipping");
          return;
        }
      }
      console.log("PyPhish: Sending analysis request to background script");
      const result = await browser.runtime.sendMessage({
        type: MSG_TYPES.ANALYZE_LINK,
        payload: { url },
      });
      console.log("PyPhish: Received result:", result);
      if (!result || result.skipped) {
        console.log("PyPhish: Result skipped or empty");
        return;
      }
      const rect = link.getBoundingClientRect();
      const x = rect.left + window.scrollX;
      const y = rect.top + window.scrollY;
      console.log(
        "PyPhish: Showing tooltip at",
        x,
        y,
        "with risk:",
        result.risk_score,
      );
      showTooltip(x, y, result);
    } catch (err) {
      console.error("PyPhish hover error:", err);
    }
  }, 250);
}

// Use both mouseover and mouseenter for better coverage
document.addEventListener("mouseover", handleMouseMove, true);
document.addEventListener("mouseenter", handleMouseMove, true);
document.addEventListener("focusin", handleMouseMove, true);
const handleMouseOut = (event) => {
  const fromLink = findLinkFromTarget(event.target);
  if (!fromLink) return;
  const toLink = findLinkFromTarget(event.relatedTarget);
  if (toLink === fromLink) return;
  currentHoverUrl = null;
  if (hoverTimer) {
    clearTimeout(hoverTimer);
    hoverTimer = null;
  }
  if (tooltipEl) {
    tooltipEl.classList.add("hidden");
  }
};

document.addEventListener("mouseout", handleMouseOut, true);
document.addEventListener("focusout", handleMouseOut, true);

browser.runtime.onMessage.addListener((message) => {
  const { type, payload } = message || {};
  if (type === MSG_TYPES.ANALYSIS_RESULT) {
    showBanner(payload);
  }
});

// Indicate extension is loaded
if (!extensionLoaded) {
  extensionLoaded = true;
  console.log(
    "%c🛡️ PyPhish Sentinel Active",
    "background: #2dd4bf; color: #0f172a; padding: 5px 10px; border-radius: 3px; font-weight: bold;",
  );
  console.log(
    "Hover over links to see phishing risk analysis. Check settings in extension popup.",
  );
}
