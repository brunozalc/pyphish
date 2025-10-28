self.PYPHISH_MESSAGES = {
  MSG_TYPES: {
    ANALYZE_LINK: "pyphish.analyze_link",
    ANALYZE_TAB: "pyphish.analyze_tab",
    ANALYSIS_RESULT: "pyphish.analysis_result",
    SETTINGS_UPDATED: "pyphish.settings_updated",
    FETCH_SETTINGS: "pyphish.fetch_settings",
    RESULT_BY_URL: "pyphish.result_by_url"
  },
  RISK_LEVELS: {
    HIGH: "ALTO",
    MEDIUM: "MÉDIO",
    LOW: "BAIXO"
  },
  isDangerous(riskScore, threshold) {
    return riskScore >= threshold;
  },
  scoreForSensitivity(sensitivity, thresholds) {
    switch (sensitivity) {
      case "high":
        return thresholds.high;
      case "low":
        return thresholds.low;
      case "medium":
      default:
        return thresholds.medium;
    }
  }
};
