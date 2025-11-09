/* global PYPHISH_MESSAGES */

/**
 * Behavioral analysis module for detecting phishing tactics:
 * - Right-click blocking
 * - URL hiding/manipulation
 * - DOM manipulation (fake overlays, address bar spoofing)
 * - Urgency timers and countdown pressure
 */

// Avoid hard dependency on messages at load time; this module doesn't need them

class BehaviorAnalyzer {
  constructor() {
    this.findings = [];
    this.hasRightClickBlock = false;
    this.hasContextMenuBlock = false;
    this.hasSelectBlock = false;
    this.hasUrlHiding = false;
    this.urgencyTimers = [];
    this.fakeOverlays = [];
    this.analyzed = false;
  }

  analyze() {
    if (this.analyzed) {
      return this.getResults();
    }

    this.checkRightClickBlocking();
    this.checkUrlManipulation();
    this.checkDomManipulation();
    this.checkUrgencyTimers();

    this.analyzed = true;
    return this.getResults();
  }

  checkRightClickBlocking() {
    // Check for contextmenu event blocking
    const contextMenuBlocked = this._isEventBlocked("contextmenu");
    if (contextMenuBlocked) {
      this.hasContextMenuBlock = true;
      this.findings.push({
        type: "right_click_block",
        severity: "medium",
        description: "Página bloqueia clique direito do mouse",
      });
    }

    // Check for selectstart blocking (prevents text selection)
    const selectBlocked = this._isEventBlocked("selectstart");
    if (selectBlocked) {
      this.hasSelectBlock = true;
      this.findings.push({
        type: "selection_block",
        severity: "low",
        description: "Página bloqueia seleção de texto",
      });
    }

    // Check for copy event blocking
    const copyBlocked = this._isEventBlocked("copy");
    if (copyBlocked) {
      this.findings.push({
        type: "copy_block",
        severity: "low",
        description: "Página bloqueia cópia de conteúdo",
      });
    }
  }

  _isEventBlocked(eventName) {
    try {
      // Check for inline event handlers that return false or call preventDefault
      const bodyHandler = document.body?.getAttribute(`on${eventName}`);
      if (bodyHandler && /return\s+false|preventDefault/.test(bodyHandler)) {
        return true;
      }

      // Check for event listeners that preventDefault
      const testElement = document.createElement("div");
      document.body?.appendChild(testElement);
      let blocked = false;

      const listener = (e) => {
        if (e.defaultPrevented) {
          blocked = true;
        }
      };

      testElement.addEventListener(eventName, listener, true);
      const event = new Event(eventName, { bubbles: true, cancelable: true });
      testElement.dispatchEvent(event);
      testElement.remove();

      return blocked;
    } catch (e) {
      return false;
    }
  }

  checkUrlManipulation() {
    try {
      // Check for fake address bars (positioned fixed/absolute at top)
      const suspiciousElements = document.querySelectorAll(
        '[class*="address"], [class*="url"], [id*="address"], [id*="url"], [class*="browser"], [id*="browser"]'
      );

      for (const el of suspiciousElements) {
        const style = window.getComputedStyle(el);
        const position = style.position;
        const top = parseFloat(style.top);
        const zIndex = parseInt(style.zIndex, 10);

        // Fake address bar at top of page with high z-index
        if (
          (position === "fixed" || position === "absolute") &&
          top < 100 &&
          zIndex > 1000
        ) {
          const text = el.textContent.toLowerCase();
          if (text.includes("http") || text.includes("www.") || text.includes(".com")) {
            this.hasUrlHiding = true;
            this.findings.push({
              type: "fake_address_bar",
              severity: "high",
              description: "Possível barra de endereço falsa detectada",
              element: {
                tag: el.tagName,
                class: el.className,
                id: el.id,
              },
            });
          }
        }
      }

      // Check for status bar manipulation
      const statusElements = document.querySelectorAll(
        '[class*="status"], [id*="status"]'
      );
      for (const el of statusElements) {
        const style = window.getComputedStyle(el);
        if (
          (style.position === "fixed" || style.position === "absolute") &&
          parseFloat(style.bottom) < 50
        ) {
          this.findings.push({
            type: "fake_status_bar",
            severity: "medium",
            description: "Possível barra de status falsa",
          });
        }
      }
    } catch (e) {
      console.warn("PyPhish: URL manipulation check error:", e);
    }
  }

  checkDomManipulation() {
    try {
      // Check for full-screen overlays that hide content
      const allElements = document.querySelectorAll("*");
      for (const el of allElements) {
        if (el === document.body || el === document.documentElement) continue;

        const style = window.getComputedStyle(el);
        const position = style.position;
        const zIndex = parseInt(style.zIndex, 10);
        const width = parseFloat(style.width);
        const height = parseFloat(style.height);

        // Large overlay with high z-index
        if (
          (position === "fixed" || position === "absolute") &&
          zIndex > 9000 &&
          width > window.innerWidth * 0.8 &&
          height > window.innerHeight * 0.8
        ) {
          // Check if it contains login forms or sensitive inputs
          const hasPasswordField = el.querySelector('input[type="password"]');
          const hasLoginForm = el.textContent.toLowerCase().match(/login|sign\s*in|entrar|senha/);

          if (hasPasswordField || hasLoginForm) {
            this.fakeOverlays.push({
              element: {
                tag: el.tagName,
                class: el.className,
                id: el.id,
              },
              hasPassword: !!hasPasswordField,
            });

            this.findings.push({
              type: "suspicious_overlay",
              severity: "high",
              description: "Overlay suspeito com formulário de login",
              details: {
                zIndex,
                hasPasswordField: !!hasPasswordField,
              },
            });
          }
        }
      }

      // Check for iframe overlays (common phishing tactic)
      const iframes = document.querySelectorAll("iframe");
      for (const iframe of iframes) {
        const style = window.getComputedStyle(iframe);
        const position = style.position;
        const zIndex = parseInt(style.zIndex, 10);

        if ((position === "fixed" || position === "absolute") && zIndex > 1000) {
          this.findings.push({
            type: "suspicious_iframe",
            severity: "medium",
            description: "Iframe posicionado como overlay",
            details: {
              src: iframe.src || "(no src)",
              zIndex,
            },
          });
        }
      }
    } catch (e) {
      console.warn("PyPhish: DOM manipulation check error:", e);
    }
  }

  checkUrgencyTimers() {
    try {
      // Look for countdown timers and urgency language
      const urgencyPatterns = [
        /\d{1,2}:\d{2}:\d{2}/g, // HH:MM:SS
        /\d{1,2}:\d{2}/g, // MM:SS
        /expires?\s+in/gi,
        /only\s+\d+\s+(minutes?|seconds?|hours?)/gi,
        /limited\s+time/gi,
        /act\s+now/gi,
        /urgent/gi,
        /expir(a|e|ing|ou)/gi,
        /apenas\s+\d+\s+(minutos?|segundos?|horas?)/gi,
        /tempo\s+limitado/gi,
        /última\s+chance/gi,
        /restam\s+apenas/gi,
      ];

      const bodyText = document.body?.textContent || "";
      let urgencyScore = 0;
      const foundPatterns = [];

      for (const pattern of urgencyPatterns) {
        const matches = bodyText.match(pattern);
        if (matches && matches.length > 0) {
          urgencyScore += matches.length;
          foundPatterns.push({
            pattern: pattern.source,
            count: matches.length,
          });
        }
      }

      // Check for elements that look like countdown timers
      const suspiciousSelectors = [
        '[id*="countdown"]',
        '[class*="countdown"]',
        '[id*="timer"]',
        '[class*="timer"]',
        '[id*="expires"]',
        '[class*="expires"]',
      ];

      for (const selector of suspiciousSelectors) {
        const elements = document.querySelectorAll(selector);
        if (elements.length > 0) {
          urgencyScore += elements.length * 2;
          this.urgencyTimers.push({
            selector,
            count: elements.length,
          });
        }
      }

      // Only flag if there's substantial urgency language/timers
      if (urgencyScore >= 3) {
        const severity = urgencyScore >= 10 ? "high" : urgencyScore >= 5 ? "medium" : "low";
        this.findings.push({
          type: "urgency_tactics",
          severity,
          description: "Página usa táticas de urgência para pressionar usuário",
          details: {
            score: urgencyScore,
            timers: this.urgencyTimers.length,
            patterns: foundPatterns.slice(0, 5), // Limit to top 5
          },
        });
      }
    } catch (e) {
      console.warn("PyPhish: Urgency timer check error:", e);
    }
  }

  getResults() {
    return {
      analyzed: this.analyzed,
      findings: this.findings,
      summary: {
        hasRightClickBlock: this.hasContextMenuBlock,
        hasSelectBlock: this.hasSelectBlock,
        hasUrlHiding: this.hasUrlHiding,
        suspiciousOverlays: this.fakeOverlays.length,
        urgencyTimers: this.urgencyTimers.length,
      },
      riskScore: this._calculateRiskScore(),
    };
  }

  _calculateRiskScore() {
    let score = 0;
    for (const finding of this.findings) {
      switch (finding.severity) {
        case "critical":
          score += 25;
          break;
        case "high":
          score += 15;
          break;
        case "medium":
          score += 8;
          break;
        case "low":
          score += 3;
          break;
      }
    }
    return Math.min(score, 100);
  }
}

// Export for use in detector.js
self.PYPHISH_BEHAVIOR = {
  BehaviorAnalyzer,
};

