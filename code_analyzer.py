import math
import re
from collections import Counter
from typing import Any, Dict, List


class CodeAnalyzer:
    """
    Analyzes JavaScript and HTML code for malicious patterns, obfuscation techniques,
    and suspicious behaviors commonly found in phishing sites.

    Detection features:
    - Obfuscation techniques (eval, base64, hex encoding, unicode escapes)
    - Suspicious JavaScript patterns (dynamic script injection, DOM manipulation)
    - Data exfiltration attempts (fetch/XHR to external domains)
    - Credential harvesting patterns
    - Encoded/hidden content
    - High entropy strings (indicator of obfuscation)
    - Suspicious function names and patterns
    """

    ENCODE_CHAR_SET = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    )
    ENCODED_SEQUENCE_REGEX = re.compile(
        r"(?:[A-Za-z0-9+/]{80,}={0,2})|(?:\\x[0-9a-fA-F]{2}){12,}|(?:%[0-9A-Fa-f]{2}){12,}"
    )
    MIN_ENTROPY_LENGTH = 300
    MIN_ENCODED_RATIO = 0.7

    # Suspicious JavaScript patterns
    SUSPICIOUS_PATTERNS = {
        "eval": {
            "pattern": r"\beval\s*\(",
            "severity": "high",
            "description": "Uso de eval() - pode executar código arbitrário",
        },
        "function_constructor": {
            "pattern": r"new\s+Function\s*\(",
            "severity": "high",
            "description": "Uso de Function() constructor - pode executar código dinâmico",
        },
        "document_write": {
            "pattern": r"document\.write\s*\(",
            "severity": "medium",
            "description": "Uso de document.write() - pode injetar código",
        },
        "innerhtml": {
            "pattern": r"\.innerHTML\s*=",
            "severity": "low",
            "description": "Manipulação direta de innerHTML",
        },
        "base64_decode": {
            "pattern": r"\batob\s*\(",
            "severity": "medium",
            "description": "Decodificação Base64 - possível ofuscação",
        },
        "fromcharcode": {
            "pattern": r"String\.fromCharCode\s*\(",
            "severity": "medium",
            "description": "Conversão de caracteres - possível ofuscação",
        },
        "settimeout_string": {
            "pattern": r'setTimeout\s*\(\s*["\']',
            "severity": "high",
            "description": "setTimeout com string - execução de código dinâmico",
        },
        "setinterval_string": {
            "pattern": r'setInterval\s*\(\s*["\']',
            "severity": "high",
            "description": "setInterval com string - execução de código dinâmico",
        },
        "script_injection": {
            "pattern": r'createElement\s*\(\s*["\']script["\']',
            "severity": "high",
            "description": "Injeção dinâmica de scripts",
        },
        "iframe_injection": {
            "pattern": r'createElement\s*\(\s*["\']iframe["\']',
            "severity": "medium",
            "description": "Criação dinâmica de iframes",
        },
        "btoa": {
            "pattern": r"btoa\s*\(",
            "severity": "low",
            "description": "Codificação Base64",
        },
        "unescape": {
            "pattern": r"unescape\s*\(",
            "severity": "medium",
            "description": "Uso de unescape() - possível ofuscação",
        },
        "hidden_redirect": {
            "pattern": r"window\.location\s*=|location\.href\s*=|location\.replace\s*\(",
            "severity": "medium",
            "description": "Redirecionamento via JavaScript",
        },
        "crypto_miner": {
            "pattern": r"coinhive|cryptonight|monero|webminer|cpuminer",
            "severity": "critical",
            "description": "Possível minerador de criptomoedas",
        },
        "keylogger": {
            "pattern": r"onkeypress|onkeydown|onkeyup|addEventListener\s*\(\s*['\"]key(press|down|up)['\"]",
            "severity": "critical",
            "description": "Possível keylogger - captura de teclado",
        },
        "clipboard_access": {
            "pattern": r'navigator\.clipboard|document\.execCommand\s*\(\s*["\']copy["\']',
            "severity": "medium",
            "description": "Acesso à área de transferência",
        },
        "webcam_access": {
            "pattern": r"getUserMedia|navigator\.mediaDevices",
            "severity": "high",
            "description": "Tentativa de acesso a câmera/microfone",
        },
        "geolocation": {
            "pattern": r"navigator\.geolocation",
            "severity": "low",
            "description": "Acesso a geolocalização",
        },
    }

    # Obfuscation indicators
    OBFUSCATION_PATTERNS = {
        "hex_encoding": {
            "pattern": r"\\x[0-9a-fA-F]{2}",
            "severity": "medium",
            "description": "Codificação hexadecimal detectada",
        },
        "unicode_escape": {
            "pattern": r"\\u[0-9a-fA-F]{4}",
            "severity": "medium",
            "description": "Escape unicode detectado",
        },
        "octal_escape": {
            "pattern": r"\\[0-7]{3}",
            "severity": "low",
            "description": "Escape octal detectado",
        },
        "long_base64": {
            "pattern": r"[A-Za-z0-9+/]{100,}={0,2}",
            "severity": "medium",
            "description": "String Base64 longa detectada",
        },
        "repeated_escape": {
            "pattern": r"(\\x|\\u|\\){10,}",
            "severity": "high",
            "description": "Múltiplos escapes consecutivos - forte ofuscação",
        },
        "var_obfuscation": {
            "pattern": r"\b[_$]+[a-zA-Z0-9_$]{0,2}\b",
            "severity": "low",
            "description": "Variáveis ofuscadas (ex: _, $, __, $_)",
        },
        "jsfuck": {
            "pattern": r"[\[\]\(\)!+]{50,}",
            "severity": "critical",
            "description": "Possível JSFuck - ofuscação extrema",
        },
        "aaencode": {
            "pattern": r"゜-゜|゜Д゜|゜∀゜",
            "severity": "critical",
            "description": "Possível AAEncode - ofuscação com caracteres japoneses",
        },
        "jjencode": {
            "pattern": r"\$={.*?\$\$.*?}\[",
            "severity": "critical",
            "description": "Possível JJEncode - ofuscação avançada",
        },
    }

    # Data exfiltration patterns
    EXFILTRATION_PATTERNS = {
        "fetch_api": {
            "pattern": r"fetch\s*\(",
            "severity": "low",
            "description": "Uso de fetch API",
        },
        "xhr": {
            "pattern": r"XMLHttpRequest|new\s+XMLHttpRequest",
            "severity": "low",
            "description": "Uso de XMLHttpRequest",
        },
        "websocket": {
            "pattern": r"new\s+WebSocket|WebSocket\s*\(",
            "severity": "medium",
            "description": "Conexão WebSocket",
        },
        "form_submit": {
            "pattern": r"\.submit\s*\(\)",
            "severity": "low",
            "description": "Submissão de formulário via JavaScript",
        },
        "localstorage_access": {
            "pattern": r"localStorage\.(getItem|setItem)|sessionStorage\.(getItem|setItem)",
            "severity": "low",
            "description": "Acesso a localStorage/sessionStorage",
        },
        "cookie_access": {
            "pattern": r"document\.cookie",
            "severity": "medium",
            "description": "Acesso a cookies",
        },
    }

    # Credential harvesting patterns
    CREDENTIAL_PATTERNS = {
        "password_field_access": {
            "pattern": r'type\s*=\s*["\']password["\'].*?\.value|password.*?\.value',
            "severity": "high",
            "description": "Acesso a campo de senha via JavaScript",
        },
        "input_value_capture": {
            "pattern": r'addEventListener\s*\(["\']input["\']|addEventListener\s*\(["\']change["\']',
            "severity": "medium",
            "description": "Captura de valores de input",
        },
        "form_data_capture": {
            "pattern": r"FormData\s*\(|new\s+FormData",
            "severity": "medium",
            "description": "Captura de dados de formulário",
        },
    }

    SCORE_WEIGHTS = {"low": 5, "medium": 15, "high": 30, "critical": 50}

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.score: int = 0

    def analyze(self, html_content: str) -> Dict[str, Any]:
        """
        Main analysis method that examines HTML/JavaScript content
        for malicious patterns and obfuscation.

        Args:
            html_content: The HTML/JavaScript source code to analyze

        Returns:
            Dictionary with analysis results including findings and risk score
        """
        self.findings = []
        self.score = 0

        results = {
            "malicious_patterns": [],
            "obfuscation_detected": [],
            "exfiltration_risks": [],
            "credential_risks": [],
            "entropy_analysis": {},
            "suspicious_scripts": [],
            "risk_score": 0,
            "risk_level": "BAIXO",
            "summary": [],
        }

        # Extract script tags
        scripts = self._extract_scripts(html_content)

        # Analyze each script
        for idx, script in enumerate(scripts):
            script_findings = self._analyze_script(script, idx)
            if script_findings:
                results["suspicious_scripts"].append(
                    {
                        "script_id": idx,
                        "preview": script[:200] if len(script) > 200 else script,
                        "findings": script_findings,
                    }
                )

        # Analyze inline JavaScript in HTML attributes
        inline_js = self._extract_inline_js(html_content)
        for js_code in inline_js:
            self._analyze_script(js_code, -1)

        # Check for suspicious patterns
        results["malicious_patterns"] = self._check_patterns(
            html_content, self.SUSPICIOUS_PATTERNS
        )

        # Check for obfuscation
        results["obfuscation_detected"] = self._check_patterns(
            html_content, self.OBFUSCATION_PATTERNS
        )

        # Check for data exfiltration
        results["exfiltration_risks"] = self._check_patterns(
            html_content, self.EXFILTRATION_PATTERNS
        )

        # Check for credential harvesting
        results["credential_risks"] = self._check_patterns(
            html_content, self.CREDENTIAL_PATTERNS
        )

        # Entropy analysis for obfuscation detection
        if scripts:
            results["entropy_analysis"] = self._analyze_entropy(scripts)

        # Calculate total risk score
        results["risk_score"] = self.score
        results["risk_level"] = self._calculate_risk_level(self.score)

        # Generate summary
        results["summary"] = self._generate_summary(results)

        return results

    def _extract_scripts(self, html: str) -> List[str]:
        """Extract all script tag contents from HTML"""
        scripts = []
        # Match script tags with their content
        script_pattern = r"<script[^>]*>(.*?)</script>"
        matches = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)

        for match in matches:
            if match.strip():
                scripts.append(match)

        return scripts

    def _extract_inline_js(self, html: str) -> List[str]:
        """Extract inline JavaScript from HTML attributes (onclick, onload, etc.)"""
        inline_js = []

        # Common event handlers
        event_attrs = [
            "onclick",
            "onload",
            "onerror",
            "onmouseover",
            "onmouseout",
            "onfocus",
            "onblur",
            "onchange",
            "onsubmit",
            "onkeydown",
            "onkeyup",
            "onkeypress",
        ]

        for attr in event_attrs:
            pattern = rf'{attr}\s*=\s*["\']([^"\']+)["\']'
            matches = re.findall(pattern, html, re.IGNORECASE)
            inline_js.extend(matches)

        # Also check for href="javascript:..."
        js_href = re.findall(
            r'href\s*=\s*["\']javascript:([^"\']+)["\']', html, re.IGNORECASE
        )
        inline_js.extend(js_href)

        return inline_js

    def _analyze_script(self, script: str, script_id: int) -> List[Dict[str, Any]]:
        """Analyze a single script for suspicious patterns"""
        findings = []
        severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        # Check for patterns in this specific script
        for category in [
            self.SUSPICIOUS_PATTERNS,
            self.OBFUSCATION_PATTERNS,
            self.EXFILTRATION_PATTERNS,
            self.CREDENTIAL_PATTERNS,
        ]:
            for name, config in category.items():
                if re.search(config["pattern"], script, re.IGNORECASE):
                    severity = config["severity"]
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    findings.append(
                        {
                            "type": name,
                            "description": config["description"],
                            "severity": severity,
                        }
                    )

        if not findings:
            return []

        if not self._should_flag_script(severity_counts):
            return []

        return findings

    def _should_flag_script(self, severity_counts: Dict[str, int]) -> bool:
        """
        Determine if a script should be considered suspicious based on the mix
        of severities that were detected inside it.
        """
        if severity_counts["critical"] > 0 or severity_counts["high"] > 0:
            return True

        medium = severity_counts["medium"]
        low = severity_counts["low"]

        if medium >= 2:
            return True

        if medium == 1 and low >= 2:
            return True

        if low >= 4:
            return True

        return False

    def _check_patterns(self, content: str, patterns: Dict) -> List[Dict[str, Any]]:
        """Check content against a set of patterns"""
        findings = []

        for name, config in patterns.items():
            matches = re.findall(config["pattern"], content, re.IGNORECASE)
            if matches:
                count = len(matches)
                finding = {
                    "type": name,
                    "description": config["description"],
                    "severity": config["severity"],
                    "count": count,
                    "samples": matches[:3] if len(matches) <= 3 else matches[:3],
                }
                findings.append(finding)

                # Add to score
                weight = self.SCORE_WEIGHTS.get(config["severity"], 5)
                # Cap the score increase per pattern type
                self.score += min(weight * count, weight * 3)

        return findings

    def _analyze_entropy(self, scripts: List[str]) -> Dict[str, Any]:
        """
        Analyze entropy of scripts to detect obfuscation.
        High entropy often indicates obfuscated or encoded content.
        """
        entropy_results = {
            "average_entropy": 0,
            "max_entropy": 0,
            "high_entropy_scripts": [],
            "is_suspicious": False,
        }

        if not scripts:
            return entropy_results

        entropies: List[float] = []
        suspicious_entropies: List[float] = []

        for idx, script in enumerate(scripts):
            entropy = self._calculate_entropy(script)
            entropies.append(entropy)

            script_len = len(script)
            encoded_ratio = self._encoded_char_ratio(script)
            has_encoded_sequence = self._has_encoded_sequence(script)

            if (
                entropy > 4.8
                and script_len >= self.MIN_ENTROPY_LENGTH
                and (encoded_ratio >= self.MIN_ENCODED_RATIO or has_encoded_sequence)
            ):
                entropy_results["high_entropy_scripts"].append(
                    {
                        "script_id": idx,
                        "entropy": round(entropy, 2),
                        "encoded_ratio": round(encoded_ratio, 2),
                        "preview": script[:100],
                    }
                )
                suspicious_entropies.append(entropy)

                if entropy > 5.6:
                    self.score += 12
                else:
                    self.score += 6

        if entropies:
            entropy_results["average_entropy"] = round(
                sum(entropies) / len(entropies), 2
            )

        if suspicious_entropies:
            entropy_results["max_entropy"] = round(max(suspicious_entropies), 2)
            entropy_results["is_suspicious"] = True
        else:
            entropy_results["max_entropy"] = 0
            entropy_results["is_suspicious"] = False

        return entropy_results

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = Counter(text)
        text_len = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _encoded_char_ratio(self, text: str) -> float:
        """Estimate how much of the text matches typical encoded payload characters"""
        if not text:
            return 0.0
        encoded_chars = sum(1 for char in text if char in self.ENCODE_CHAR_SET)
        return encoded_chars / len(text)

    def _has_encoded_sequence(self, text: str) -> bool:
        """Detect long encoded sequences even if the overall ratio is low"""
        return bool(self.ENCODED_SEQUENCE_REGEX.search(text))

    def _calculate_risk_level(self, score: int) -> str:
        """Calculate risk level based on score"""
        if score >= 70:
            return "ALTO"
        elif score >= 40:
            return "MÉDIO"
        else:
            return "BAIXO"

    def _generate_summary(self, results: Dict[str, Any]) -> List[str]:
        """Generate human-readable summary of findings"""
        summary = []

        # Count critical/high severity findings
        critical_count = 0
        high_count = 0

        for category in [
            "malicious_patterns",
            "obfuscation_detected",
            "exfiltration_risks",
            "credential_risks",
        ]:
            for finding in results.get(category, []):
                if finding["severity"] == "critical":
                    critical_count += 1
                elif finding["severity"] == "high":
                    high_count += 1

        if critical_count > 0:
            summary.append(f"⚠️ {critical_count} padrões críticos detectados")

        if high_count > 0:
            summary.append(f"⚠️ {high_count} padrões de alta severidade detectados")

        if results.get("obfuscation_detected"):
            summary.append(
                f"Técnicas de ofuscação detectadas: {len(results['obfuscation_detected'])}"
            )

        if results.get("entropy_analysis", {}).get("is_suspicious"):
            summary.append("Alta entropia detectada - possível código ofuscado")

        if results.get("credential_risks"):
            summary.append("Padrões de captura de credenciais detectados")

        if results.get("suspicious_scripts"):
            summary.append(
                f"{len(results['suspicious_scripts'])} scripts suspeitos encontrados"
            )

        if not summary:
            summary.append("Nenhum padrão suspeito detectado no código-fonte")

        return summary
