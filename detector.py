from typing import Dict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from analyzer import URLAnalyzer
from lists import PhishingListChecker


class PhishingDetector:
    def __init__(self):
        self.list_checker = PhishingListChecker()
        self.url_analyzer = URLAnalyzer()
        # Pre-load lists into memory to avoid reloading on every request
        print("🔄 Pre-loading phishing lists into memory...")
        self._warmup_cache()

    def _warmup_cache(self):
        """Pre-load all lists to speed up first request"""
        try:
            # This will load and cache all lists in the PhishingListChecker
            self.list_checker.check_custom_database("http://warmup.test")
            self.list_checker.check_phishtank("http://warmup.test")
            self.list_checker.check_openphish("http://warmup.test")
            print("✅ Lists pre-loaded successfully")
        except Exception as e:
            print(f"⚠️  Warning: Could not pre-load all lists: {e}")

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
            try:
                # Run list checks with a 5s timeout using a thread (signals don't work off main thread)
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(self._check_phishing_lists, url)
                    results["checks"]["phishing_lists"] = future.result(timeout=5)

                if results["checks"]["phishing_lists"].get("found_in_lists"):
                    results["is_phishing"] = True
                    results["risk_level"] = "ALTO"
                    results["risk_score"] = 100
                    results["summary"].append(
                        "URL encontrada em lista de phishing conhecida"
                    )
            except FuturesTimeoutError:
                print("⚠️  List checking timed out, skipping...")
                results["checks"]["phishing_lists"] = {
                    "custom_database": {"is_phishing": False, "message": "Timeout"},
                    "phishtank": {"is_phishing": False, "message": "Timeout"},
                    "openphish": {"is_phishing": False, "message": "Timeout"},
                    "found_in_lists": False,
                }
            except Exception as e:
                print(f"⚠️  List checking error: {e}")
                results["checks"]["phishing_lists"] = {
                    "custom_database": {"is_phishing": False, "message": str(e)},
                    "phishtank": {"is_phishing": False, "message": str(e)},
                    "openphish": {"is_phishing": False, "message": str(e)},
                    "found_in_lists": False,
                }

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

        # Check custom database first (fastest and local)
        try:
            is_phishing, message = self.list_checker.check_custom_database(url)
            results["custom_database"] = {
                "is_phishing": is_phishing,
                "message": message,
            }
            if is_phishing:
                results["found_in_lists"] = True
                return results  # Return immediately if found
        except Exception as e:
            print(f"⚠️  Custom DB check failed: {e}")
            results["custom_database"] = {"is_phishing": False, "message": str(e)}

        # Skip external list checks to avoid timeouts
        # They will use cache if available
        try:
            is_phishing, message = self.list_checker.check_phishtank(url)
            results["phishtank"] = {"is_phishing": is_phishing, "message": message}
            if is_phishing:
                results["found_in_lists"] = True
        except Exception as e:
            print(f"⚠️  PhishTank check failed: {e}")
            results["phishtank"] = {"is_phishing": False, "message": str(e)}

        try:
            is_phishing, message = self.list_checker.check_openphish(url)
            results["openphish"] = {"is_phishing": is_phishing, "message": message}
            if is_phishing:
                results["found_in_lists"] = True
        except Exception as e:
            print(f"⚠️  OpenPhish check failed: {e}")
            results["openphish"] = {"is_phishing": False, "message": str(e)}

        return results

    def _calculate_risk_level(self, score: int) -> str:
        if score >= 70:
            return "ALTO"
        elif score >= 40:
            return "MÉDIO"
        else:
            return "BAIXO"
