(function () {
  const {
    DEFAULT_SETTINGS,
    STORAGE_KEYS,
    CACHE_TTL_MS
  } = self.PYPHISH_CONSTANTS;

  const cache = new Map();

  async function getSettings() {
    const stored = await browser.storage.sync.get(STORAGE_KEYS.settings);
    if (stored && stored[STORAGE_KEYS.settings]) {
      const merged = { ...DEFAULT_SETTINGS, ...stored[STORAGE_KEYS.settings] };
      merged.whitelist = Array.isArray(merged.whitelist)
        ? merged.whitelist.filter(Boolean)
        : [];
      return merged;
    }
    return { ...DEFAULT_SETTINGS };
  }

  async function saveSettings(nextSettings) {
    const settings = { ...DEFAULT_SETTINGS, ...nextSettings };
    await browser.storage.sync.set({
      [STORAGE_KEYS.settings]: settings
    });
    return settings;
  }

  function normalizeUrl(url) {
    try {
      const u = new URL(url);
      return u.hostname.replace(/^www\./, "");
    } catch (err) {
      return url.replace(/^https?:\/\//, "").split("/")[0];
    }
  }

  function isWhitelisted(url, whitelist = []) {
    const host = normalizeUrl(url);
    return whitelist.some((entry) => {
      const normalized = entry.trim().toLowerCase();
      if (!normalized) return false;
      if (normalized.startsWith("*")) {
        const suffix = normalized.slice(1);
        return host.endsWith(suffix);
      }
      return host === normalizeUrl(normalized);
    });
  }

  function cacheResult(url, data, ttlMs = CACHE_TTL_MS) {
    cache.set(url, { data, expires: Date.now() + ttlMs });
  }

  function getCachedResult(url) {
    const hit = cache.get(url);
    if (!hit) return null;
    if (Date.now() > hit.expires) {
      cache.delete(url);
      return null;
    }
    return hit.data;
  }

  function clearCache() {
    cache.clear();
  }

  self.PYPHISH_STATE = {
    getSettings,
    saveSettings,
    normalizeUrl,
    isWhitelisted,
    cacheResult,
    getCachedResult,
    clearCache
  };
})();
