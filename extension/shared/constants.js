self.PYPHISH_CONSTANTS = {
  DEFAULT_API_BASE: "http://localhost:5000",
  ANALYZE_ENDPOINT: "/analyze",
  RISK_THRESHOLDS: {
    low: 30,
    medium: 60,
    high: 80
  },
  DEFAULT_SETTINGS: {
    sensitivity: "medium",
    autoBlock: false,
    hoverAnalysis: true,
    notifications: true,
    whitelist: [],
    apiBase: "http://localhost:5000"
  },
  BADGE_COLORS: {
    safe: "#2dd4bf",
    warning: "#facc15",
    danger: "#f87171",
    neutral: "#6b7280"
  },
  STORAGE_KEYS: {
    settings: "pyphish.settings",
    cache: "pyphish.cache"
  },
  CACHE_TTL_MS: 5 * 60 * 1000
};
