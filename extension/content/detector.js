/* global PYPHISH_MESSAGES, PYPHISH_BEHAVIOR */

const { MSG_TYPES, RISK_LEVELS } = PYPHISH_MESSAGES;
let BehaviorAnalyzerCtor = null;
try {
  if (
    typeof PYPHISH_BEHAVIOR !== "undefined" &&
    PYPHISH_BEHAVIOR &&
    PYPHISH_BEHAVIOR.BehaviorAnalyzer
  ) {
    BehaviorAnalyzerCtor = PYPHISH_BEHAVIOR.BehaviorAnalyzer;
  }
} catch (e) {
  // Behavior module may not be available on all pages; hover analysis should still work
}

let tooltipEl;
let bannerEl;
let hideTimeout;
let currentHoverUrl = null;
let hoverTimer;
let settingsCache = null;
let settingsFetchedAt = 0;
let extensionLoaded = false;
let behaviorAnalyzer = null;
let behaviorAnalysisScheduled = false;

function coerceElement(target) {
  if (!target) return null;
  if (target instanceof Element) return target;
  if (typeof Node !== "undefined" && target.nodeType === Node.TEXT_NODE) {
    return target.parentElement;
  }
  return null;
}

function findLinkFromTarget(event) {
  if (!event) return null;

  // Modern approach: Use event.composedPath() to correctly handle Shadow DOM
  if (typeof event.composedPath === "function") {
    for (const element of event.composedPath()) {
      if (element.nodeName === "A" && element.href) {
        return element;
      }
    }
  }

  // Fallback for older browsers or if composedPath fails
  const element = coerceElement(event.target);
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

  // Show risk level and score, plus a truncated URL
  const displayUrl =
    result.url.length > 50 ? result.url.substring(0, 47) + "..." : result.url;
  const originalUrl = result.details && result.details.original_url;
  const showOriginal = originalUrl && originalUrl !== result.url;
  const displayOriginal = showOriginal
    ? originalUrl.length > 50
      ? originalUrl.substring(0, 47) + "..."
      : originalUrl
    : null;
  el.innerHTML = `
    <div style="font-weight: bold; margin-bottom: 3px;">${result.risk_level} (${
    result.risk_score
  }%)</div>
    <div style="font-size: 10px; opacity: 0.8;">Destino: ${displayUrl}</div>
    ${
      showOriginal
        ? `<div style="font-size: 10px; opacity: 0.7;">Encurtada de: ${displayOriginal}</div>`
        : ""
    }
  `;

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
  const originalUrl = result.details && result.details.original_url;
  const showOriginal = originalUrl && originalUrl !== result.url;
  const description = showOriginal
    ? `${result.url}\n(Encurtada de: ${originalUrl})\nRisco: ${result.risk_level} (${result.risk_score}%)`
    : `${result.url}\nRisco: ${result.risk_level} (${result.risk_score}%)`;
  el.querySelector(".pyphish-desc").textContent = description;
  el.className = `pyphish-banner ${riskClass(result.risk_level)}`;
}

function handleMouseMove(event) {
  try {
    const link = findLinkFromTarget(event);
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

    // Extract actual URL from common email redirect/tracking patterns
    if (url) {
      try {
        const urlObj = new URL(url, window.location.href);

        // Gmail/Google SafeBrowsing: /url?q=https://actual-url.com&sa=...
        if (url.includes("/url?q=") || url.includes("google.com/url")) {
          const actualUrl = urlObj.searchParams.get("q");
          if (actualUrl && /^https?:/.test(actualUrl)) {
            console.log("PyPhish: Extracted from Google redirect:", actualUrl);
            url = actualUrl;
          }
        }

        // Outlook SafeLinks: safelinks.protection.outlook.com/?url=...
        else if (url.includes("safelinks.protection.outlook.com")) {
          const actualUrl = urlObj.searchParams.get("url");
          if (actualUrl && /^https?:/.test(actualUrl)) {
            console.log(
              "PyPhish: Extracted from Outlook SafeLinks:",
              actualUrl
            );
            url = actualUrl;
          }
        }

        // Generic tracking redirects: ?url=... or ?redirect=... or ?target=...
        else if (urlObj.searchParams.has("url")) {
          const actualUrl = urlObj.searchParams.get("url");
          if (actualUrl && /^https?:/.test(actualUrl)) {
            console.log(
              "PyPhish: Extracted from tracking URL (url param):",
              actualUrl
            );
            url = actualUrl;
          }
        } else if (urlObj.searchParams.has("redirect")) {
          const actualUrl = urlObj.searchParams.get("redirect");
          if (actualUrl && /^https?:/.test(actualUrl)) {
            console.log(
              "PyPhish: Extracted from tracking URL (redirect param):",
              actualUrl
            );
            url = actualUrl;
          }
        } else if (urlObj.searchParams.has("target")) {
          const actualUrl = urlObj.searchParams.get("target");
          if (actualUrl && /^https?:/.test(actualUrl)) {
            console.log(
              "PyPhish: Extracted from tracking URL (target param):",
              actualUrl
            );
            url = actualUrl;
          }
        }
      } catch (e) {
        // If parsing fails, use original URL
        console.log("PyPhish: Could not parse redirect URL, using original");
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
          settings.hoverAnalysis
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
          result.risk_score
        );
        showTooltip(x, y, result);
      } catch (err) {
        console.error("PyPhish hover error:", err);
      }
    }, 250);
  } catch (err) {
    console.error("PyPhish: Error in handleMouseMove:", err);
  }
}

const handleMouseOut = (event) => {
  try {
    const fromLink = findLinkFromTarget(event);
    if (!fromLink) return;
    const toElement = coerceElement(event.relatedTarget);
    const toLink = toElement ? toElement.closest("a[href], area[href]") : null;
    if (toLink === fromLink) return;
    currentHoverUrl = null;
    if (hoverTimer) {
      clearTimeout(hoverTimer);
      hoverTimer = null;
    }
    if (tooltipEl) {
      tooltipEl.classList.add("hidden");
    }
  } catch (err) {
    console.error("PyPhish: Error in handleMouseOut:", err);
  }
};

function initializeEventListeners() {
  try {
    console.log("PyPhish: Initializing event listeners...");

    // Use both mouseover and mouseenter for better coverage
    document.addEventListener("mouseover", handleMouseMove, true);
    document.addEventListener("mouseenter", handleMouseMove, true);
    document.addEventListener("focusin", handleMouseMove, true);
    document.addEventListener("mouseout", handleMouseOut, true);
    document.addEventListener("focusout", handleMouseOut, true);

    console.log("PyPhish: Event listeners registered successfully");
  } catch (err) {
    console.error("PyPhish: Failed to register event listeners:", err);
  }
}

browser.runtime.onMessage.addListener((message) => {
  const { type, payload } = message || {};
  if (type === MSG_TYPES.ANALYSIS_RESULT) {
    showBanner(payload);
  } else if (type === MSG_TYPES.REQUEST_BEHAVIOR_ANALYSIS) {
    return performBehaviorAnalysis();
  }
});

function performBehaviorAnalysis() {
  try {
    // Ensure BehaviorAnalyzer is available
    if (!BehaviorAnalyzerCtor) {
      try {
        if (
          typeof PYPHISH_BEHAVIOR !== "undefined" &&
          PYPHISH_BEHAVIOR &&
          PYPHISH_BEHAVIOR.BehaviorAnalyzer
        ) {
          BehaviorAnalyzerCtor = PYPHISH_BEHAVIOR.BehaviorAnalyzer;
        }
      } catch (e) {}
    }
    if (!BehaviorAnalyzerCtor) {
      return Promise.resolve({
        analyzed: false,
        error: "BehaviorAnalyzer not loaded",
      });
    }
    if (!behaviorAnalyzer) {
      behaviorAnalyzer = new BehaviorAnalyzerCtor();
    }
    const results = behaviorAnalyzer.analyze();
    console.log("PyPhish: Behavior analysis results:", results);
    return Promise.resolve(results);
  } catch (err) {
    console.error("PyPhish: Behavior analysis error:", err);
    return Promise.resolve({ analyzed: false, error: err.message });
  }
}

function scheduleBehaviorAnalysis() {
  if (behaviorAnalysisScheduled) return;
  behaviorAnalysisScheduled = true;

  // Wait for page to load and stabilize before analyzing
  if (document.readyState === "complete") {
    setTimeout(() => {
      performBehaviorAnalysis().then((results) => {
        if (results.findings && results.findings.length > 0) {
          browser.runtime
            .sendMessage({
              type: MSG_TYPES.BEHAVIOR_ANALYSIS_RESULT,
              payload: {
                url: window.location.href,
                results,
              },
            })
            .catch((err) =>
              console.warn("PyPhish: Failed to send behavior results:", err)
            );
        }
      });
    }, 2000);
  } else {
    window.addEventListener("load", () => {
      setTimeout(() => {
        performBehaviorAnalysis().then((results) => {
          if (results.findings && results.findings.length > 0) {
            browser.runtime
              .sendMessage({
                type: MSG_TYPES.BEHAVIOR_ANALYSIS_RESULT,
                payload: {
                  url: window.location.href,
                  results,
                },
              })
              .catch((err) =>
                console.warn("PyPhish: Failed to send behavior results:", err)
              );
          }
        });
      }, 2000);
    });
  }
}

// Initialize the extension
function initializeExtension() {
  if (extensionLoaded) return;
  extensionLoaded = true;

  console.log(
    "%c🛡️ PyPhish Sentinel Active",
    "background: #2dd4bf; color: #0f172a; padding: 5px 10px; border-radius: 3px; font-weight: bold;"
  );
  console.log(
    "Hover over links to see phishing risk analysis. Check settings in extension popup."
  );

  // Initialize event listeners
  initializeEventListeners();

  // Schedule behavioral analysis for main page navigation
  scheduleBehaviorAnalysis();
}

// Initialize immediately if DOM is ready, otherwise wait
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeExtension);
} else {
  initializeExtension();
}
