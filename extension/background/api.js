(function () {
  const { ANALYZE_ENDPOINT } = self.PYPHISH_CONSTANTS;

  async function requestApi(path, payload, baseUrl) {
    const url = new URL(path, baseUrl);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(url.toString(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return await response.json();
    } finally {
      clearTimeout(timeout);
    }
  }

  async function analyzeUrl(url, baseUrl) {
    try {
      const data = await requestApi(
        ANALYZE_ENDPOINT,
        { url, check_lists: true },
        baseUrl
      );
      if (data.error) {
        throw new Error(data.message || "Erro desconhecido");
      }
      return data.results;
    } catch (error) {
      console.warn("PyPhish API error", error);
      return {
        url,
        is_phishing: false,
        risk_level: "DESCONHECIDO",
        risk_score: 0,
        summary: [error.message || "Falha ao consultar API"],
        error: true
      };
    }
  }

  self.PYPHISH_API = {
    analyzeUrl
  };
})();
