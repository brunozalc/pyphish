from typing import Dict

from analyzer import URLAnalyzer
from lists import PhishingListChecker


class PhishingDetector:
    def __init__(self):
        self.list_checker = PhishingListChecker()
        self.url_analyzer = URLAnalyzer()

    def analyze_url(self, url: str, check_lists: bool = True) -> Dict:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        results = {
            "url": url,
            "is_phishing": False,
            "risk_level": "BAIXO",
            "risk_score": 0,
            "checks": {"phishing_lists": {}, "url_analysis": {}},
            "summary": [],
        }

        if check_lists:
            results["checks"]["phishing_lists"] = self._check_phishing_lists(url)

            if results["checks"]["phishing_lists"].get("found_in_lists"):
                results["is_phishing"] = True
                results["risk_level"] = "ALTO"
                results["risk_score"] = 100
                results["summary"].append(
                    "URL encontrada em lista de phishing conhecida"
                )

        url_analysis = self.url_analyzer.analyze(url)
        results["checks"]["url_analysis"] = url_analysis

        if not results["is_phishing"]:
            results["risk_score"] = min(url_analysis["risk_score"], 100)
            results["risk_level"] = self._calculate_risk_level(results["risk_score"])
            results["summary"] = url_analysis["suspicious_features"]

        return results

    def _check_phishing_lists(self, url: str) -> Dict:
        results = {
            "custom_database": {},
            "phishtank": {},
            "openphish": {},
            "found_in_lists": False,
        }

        # Check custom database first (fastest)
        is_phishing, message = self.list_checker.check_custom_database(url)
        results["custom_database"] = {"is_phishing": is_phishing, "message": message}
        if is_phishing:
            results["found_in_lists"] = True

        # Check PhishTank
        is_phishing, message = self.list_checker.check_phishtank(url)
        results["phishtank"] = {"is_phishing": is_phishing, "message": message}
        if is_phishing:
            results["found_in_lists"] = True

        # Check OpenPhish
        is_phishing, message = self.list_checker.check_openphish(url)
        results["openphish"] = {"is_phishing": is_phishing, "message": message}
        if is_phishing:
            results["found_in_lists"] = True

        return results

    def _calculate_risk_level(self, score: int) -> str:
        if score >= 70:
            return "ALTO"
        elif score >= 40:
            return "MÉDIO"
        else:
            return "BAIXO"
