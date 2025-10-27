import re
from typing import Dict
from urllib.parse import urlparse


class URLAnalyzer:
    LETTER_NUMBER_SUBSTITUTIONS = {
        "o": "0",
        "i": "1",
        "l": "1",
        "e": "3",
        "a": "4",
        "s": "5",
        "g": "9",
        "b": "8",
    }

    def __init__(self):
        self.suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
        self.common_brands = [
            "paypal",
            "amazon",
            "google",
            "facebook",
            "microsoft",
            "apple",
            "netflix",
            "instagram",
            "twitter",
            "linkedin",
            "banco",
            "bradesco",
            "itau",
            "santander",
            "caixa",
            "nubank",
            "inter",
        ]

    def analyze(self, url: str) -> Dict:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            results = {
                "url": url,
                "domian": domain,
                "suspicious_features": [],
                "risk_score": 0,
                "details": {},
            }

            if not domain:
                results["suspicious_features"].append("URL inválida")
                results["risk_score"] = 100
                return results

            self._check_number_substitution(domain, results)
            self._check_excessive_subdomains(domain, results)
            self._check_special_characters(domain, results)
            self._check_suspicious_tld(parsed.netloc, results)
            self._check_ip_address(domain, results)
            self._check_url_length(url, results)
            self._check_brand_impersonation(domain, results)
            self._check_suspicious_keywords(url, results)

            return results

        except Exception as e:
            return {
                "url": url,
                "domain": domain,
                "suspicious_features": [f"Erro ao analisar URL: {str(e)}"],
                "risk_score": 50,
                "details": {},
            }

    def _check_number_substitution(self, domain: str, results: Dict):
        substitutions_found = []

        for letter, number in self.LETTER_NUMBER_SUBSTITUTIONS.items():
            if number in domain:
                pattern = f"{number}"
                if re.search(pattern, domain):
                    substitutions_found.append(f"'{number}' pode substituir '{letter}'")

        if substitutions_found:
            results["suspicious_feature"].append("Números em substituição a letras")
            results["details"]["number_substitution"] = substitutions_found
            results["risk_score"] += 20

    def _check_excessive_subdomains(self, domain: str, results: Dict):
        parts = domain.split(".")

        if ":" in parts[-1]:
            parts[-1] = parts[-1].split(":")[0]

        subdomain_count = len(parts) - 2

        if subdomain_count > 2:
            results["suspicious_feature"].append("Uso excessivo de subdomínios")
            results["details"]["subdomain_count"] = subdomain_count
            results["details"]["subdomains"] = ".".join(parts[:-2])
            results["risk_score"] += 25
        elif subdomain_count > 1:
            results["details"]["subdomain_count"] = subdomain_count
            results["risk_score"] += 10

    def _check_special_characters(self, domain: str, results: Dict):
        special_chars = ["-", "_"]
        found_chars = []

        for char in special_chars:
            count = domain.count(char)
            if count > 2:
                found_chars.append(f"'{char}' aparece {count} vezes")

        if found_chars:
            results["suspicious_feature"].append("Caracteres especiais em excesso")
            results["details"]["special_characters"] = found_chars
            results["risk_score"] += 15

    def _check_suspicious_tld(self, domain: str, results: Dict):
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                results["suspicious_feature"].append(f"TLD suspeito: {tld}")
                results["details"]["suspicious_tld"] = tld
                results["risk_score"] += 30
                break

    def _check_ip_address(self, domain: str, results: Dict):
        domain_without_port = domain.split(":")[0]

        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, domain_without_port):
            results["suspicious_features"].append("URL usa endereço IP")
            results["details"]["ip_address"] = domain_without_port
            results["risk_score"] += 35

    def _check_url_length(self, url: str, results: Dict):
        if len(url) > 75:
            results["suspicious_features"].append("URL muito longa")
            results["details"]["url_length"] = len(url)
            results["risk_score"] += 10

    def _check_brand_impersonation(self, domain: str, results: Dict):
        for brand in self.common_brands:
            if brand in domain:
                if not domain.endswith(f"{brand}.com") and not domain.endswith(
                    f"{brand}.com.br"
                ):
                    results["suspicious_features"].append(
                        f"Possível imitação de marca: {brand}"
                    )
                    results["details"]["brand_impersonation"] = brand
                    results["risk_score"] += 40
                    break

    def _check_suspicious_keywords(self, url: str, results: Dict):
        suspicious_keywords = [
            "login",
            "signin",
            "account",
            "verify",
            "secure",
            "update",
            "confirm",
            "banking",
            "suspend",
            "password",
            "credential",
            "conta",
            "cadastro",
            "registro",
            "pagamento",
            "pagar",
            "senha",
            "suspender",
            "cancelar",
            "cancel",
        ]

        url_lower = url.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]

        if found_keywords:
            results["details"]["suspicious_keywords"] = found_keywords
            results["risk_score"] += len(found_keywords) * 5
