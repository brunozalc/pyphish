(function () {
  const { ANALYZE_ENDPOINT } = self.PYPHISH_CONSTANTS;

  async function requestApi(path, payload, baseUrl) {
    const url = new URL(path, baseUrl);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(url.toString(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
        credentials: "omit",
        mode: "cors",
      });
      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        throw new Error(
          `HTTP ${response.status}: ${errorText || response.statusText}`,
        );
      }
      return await response.json();
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error("Timeout ao conectar com API (10s)");
      }
      if (
        error.message.includes("NetworkError") ||
        error.message.includes("Failed to fetch")
      ) {
        throw new Error(
          "Não foi possível conectar ao servidor. Verifique se está rodando em " +
            baseUrl,
        );
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function analyzeUrl(url, baseUrl) {
    try {
      const data = await requestApi(
        ANALYZE_ENDPOINT,
        { url, check_lists: true },
        baseUrl,
      );
      if (data.error) {
        throw new Error(data.message || "Erro desconhecido");
      }
      return data.results;
    } catch (error) {
      console.warn("PyPhish API error:", error.message);
      return {
        url,
        is_phishing: false,
        risk_level: "DESCONHECIDO",
        risk_score: 0,
        summary: [error.message || "Falha ao consultar API"],
        error: true,
      };
    }
  }

  self.PYPHISH_API = {
    analyzeUrl,
  };
})();
