import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests

from code_analyzer import CodeAnalyzer


class URLAnalyzer:
    """
    Advanced heuristic analyzer for phishing detection.

    Features:
    - Heuristics (subdomains, TLD, IP usage, substitutions, brand impersonation)
    - WHOIS: domain age estimation
    - Dynamic DNS provider detection
    - SSL certificate checks (issuer, expiration, hostname match)
    - Redirect analysis (depth, cross-domain)
    - Levenshtein similarity against known brands
    - Basic content scan for login forms and sensitive keywords

    Output schema:
    {
        "url": str,
        "domain": str,
        "suspicious_features": List[str],
        "risk_score": int (0-100),
        "details": Dict[str, Any]
    }
    """

    LETTER_NUMBER_SUBSTITUTIONS: dict[str, str] = {
        "o": "0",
        "i": "1",
        "l": "1",
        "e": "3",
        "a": "4",
        "s": "5",
        "g": "9",
        "b": "8",
        "t": "7",
    }

    # Naive, pragmatic list (expand as needed)
    SUSPICIOUS_TLDS: list[str] = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
        ".work",
        ".cam",
        ".shop",
        ".online",
        ".click",
        ".link",
        ".fit",
        ".rest",
        ".lol",
        ".icu",
        ".monster",
        ".buzz",
    ]

    DYNAMIC_DNS_SUFFIXES: list[str] = [
        "no-ip.com",
        "duckdns.org",
        "dyndns.org",
        "ddns.net",
        "dynu.net",
        "hopto.org",
        "zapto.org",
        "changeip.com",
        "freedns.afraid.org",
        "mooo.com",
        "twilightparadox.com",  # some custom ddns providers
    ]

    COMMON_BRANDS: list[str] = [
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
        "bradesco",
        "itau",
        "santander",
        "nubank",
        "bancointer",
        "whatsapp",
        "outlook",
        "office",
        "oneDrive".lower(),
        "coinbase",
        "binance",
    ]

    USER_AGENT: str = "PyPhish/1.0 (+https://example.local)"

    # Legitimate authentication/SSO domains that commonly have very long URLs
    # These domains should not be penalized for URL length
    LEGITIMATE_AUTH_DOMAINS: list[str] = [
        "accounts.google.com",
        "accounts.youtube.com",
        "login.microsoftonline.com",
        "login.live.com",
        "login.windows.net",
        "oauth.vk.com",
        "api.twitter.com",
        "oauth.twitter.com",
        "www.facebook.com",
        "m.facebook.com",
        "appleid.apple.com",
        "idmsa.apple.com",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "id.atlassian.com",
        "auth.atlassian.com",
        "slack.com",
        "discord.com",
        "steamcommunity.com",
        "store.steampowered.com",
        "auth0.com",
        "okta.com",
        "onelogin.com",
        "sso.godaddy.com",
        "auth.gog.com",
        "oauth.reddit.com",
        "linkedin.com",
        "api.linkedin.com",
        "zoom.us",
        "signin.aws.amazon.com",
        "console.aws.amazon.com",
    ]

    SCORE_WEIGHTS: dict[str, float] = {
        "low": 0.12,
        "medium": 0.22,
        "high": 0.4,
        "critical": 0.55,
    }

    def __init__(self, http_timeout: int = 2, tcp_timeout: int = 2):
        self.http_timeout: int = http_timeout
        self.tcp_timeout: int = tcp_timeout
        # extend defaults without duplicating
        if ".gift" not in self.SUSPICIOUS_TLDS:
            self.SUSPICIOUS_TLDS.append(".gift")
        if "discord" not in self.COMMON_BRANDS:
            self.COMMON_BRANDS.append("discord")

    # ---------------------------
    # Public API
    # ---------------------------
    def analyze(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url)
        domain = self._extract_domain(parsed)

        results: dict[str, Any] = {
            "url": url,
            "domain": domain or "",
            "suspicious_features": [],
            "risk_score": 0,
            "details": {},
        }

        if not domain:
            self._add_signal(results, "URL inválida",
                             severity="critical", weight=1.0)
            self._finalize_score(results)
            results["suspicious_features"] = list(
                dict.fromkeys(results["suspicious_features"])
            )
            return results

        # heuristic checks
        self._check_number_substitution(domain, results)
        self._check_excessive_subdomains(domain, results)
        self._check_special_characters(domain, results)
        self._check_suspicious_tld(domain, results)
        self._check_ip_address(domain, results)
        self._check_url_length(url, results)
        self._check_brand_impersonation_and_similarity(domain, results)

        # dynamic DNS
        self._check_dynamic_dns(domain, results)

        # SSL certificate (with timeout protection)
        try:
            self._check_ssl_certificate(domain, results)
        except Exception as e:
            results["details"]["ssl_error"] = str(e)

        # WHOIS age (with timeout protection)
        try:
            self._check_whois_age(domain, results)
        except Exception as e:
            results["details"]["whois_error"] = str(e)

        # redirects + basic content scan (with timeout protection)
        try:
            self._check_redirects_and_content(url, results)
        except Exception as e:
            results["details"]["redirect_error"] = str(e)

        self._finalize_score(results)

        # sort/remove duplicates in suspicious_features
        results["suspicious_features"] = list(
            dict.fromkeys(results["suspicious_features"])
        )

        return results

    # ---------------------------
    # Heuristics
    # ---------------------------
    def _add_signal(
        self,
        results: dict,
        description: str,
        severity: str = "low",
        weight: Optional[float] = None,
        include_summary: bool = True,
    ) -> None:
        """
        Register a heuristic signal and map it to a probabilistic weight.
        The weights are combined later assuming independent evidence,
        avoiding unbounded additive scores while keeping the summary readable.
        """
        if weight is None:
            weight = self.SCORE_WEIGHTS.get(
                severity, self.SCORE_WEIGHTS["low"])

        breakdown = results.setdefault(
            "details", {}).setdefault("score_breakdown", [])
        breakdown.append(
            {
                "reason": description,
                "severity": severity,
                "weight": max(0.0, min(1.0, weight)),
            }
        )

        if include_summary:
            results["suspicious_features"].append(description)

    def _finalize_score(self, results: dict) -> None:
        """Aggregate all registered signals into a bounded 0-100 risk score."""
        components = results.get("details", {}).get("score_breakdown", [])
        residual_risk = 1.0
        for comp in components:
            residual_risk *= 1.0 - comp["weight"]
        aggregated = 1.0 - residual_risk
        results["risk_score"] = int(round(aggregated * 100))

    def _check_number_substitution(self, domain: str, results: dict):
        occurrences: List[str] = []
        for letter, number in self.LETTER_NUMBER_SUBSTITUTIONS.items():
            if number in domain:
                # Attempt to pair number back to similar letters in the domain pattern context
                occurrences.append(f"'{number}' pode substituir '{letter}'")

        if occurrences:
            self._add_signal(
                results,
                "Números em substituição a letras (typosquatting)",
                severity="medium",
                weight=0.18,
            )
            results["details"]["number_substitution"] = occurrences

    def _check_excessive_subdomains(self, domain: str, results: dict):
        parts = domain.split(".")
        if parts and ":" in parts[-1]:
            parts[-1] = parts[-1].split(":")[0]

        subdomain_count = max(0, len(parts) - 2)
        if subdomain_count > 2:
            self._add_signal(
                results,
                "Uso excessivo de subdomínios",
                severity="high",
                weight=0.32,
            )
            results["details"]["subdomain_count"] = subdomain_count
            results["details"]["subdomains"] = ".".join(parts[:-2])
        elif subdomain_count > 1:
            results["details"]["subdomain_count"] = subdomain_count
            self._add_signal(
                results,
                "Domínio com múltiplos subdomínios incomuns",
                severity="medium",
                weight=0.14,
                include_summary=False,
            )

    def _check_special_characters(self, domain: str, results: dict):
        special_chars = ["-", "_"]
        found: List[str] = []
        for ch in special_chars:
            count = domain.count(ch)
            if count > 3:
                found.append(f"'{ch}' aparece {count} vezes")

        if found:
            self._add_signal(
                results,
                "Caracteres especiais em excesso",
                severity="medium",
                weight=0.2,
            )
            results["details"]["special_characters"] = found

    def _check_suspicious_tld(self, domain: str, results: dict):
        d = domain.lower()
        for tld in self.SUSPICIOUS_TLDS:
            if d.endswith(tld):
                self._add_signal(
                    results,
                    f"TLD suspeito: {tld}",
                    severity="high",
                    weight=0.4,
                )
                results["details"]["suspicious_tld"] = tld
                break

    def _check_ip_address(self, domain: str, results: dict):
        host = domain.split(":")[0]
        ip_pattern = r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
        if re.match(ip_pattern, host):
            self._add_signal(
                results,
                "URL usa endereço IP",
                severity="critical",
                weight=0.6,
            )
            results["details"]["ip_address"] = host

    def _check_url_length(self, url: str, results: dict):
        L = len(url)

        # Check if this is a legitimate auth/SSO domain that commonly has long URLs
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Skip length check for legitimate authentication domains
            for auth_domain in self.LEGITIMATE_AUTH_DOMAINS:
                if domain == auth_domain or domain.endswith("." + auth_domain):
                    results["details"]["url_length"] = L
                    results["details"]["auth_domain_exception"] = True
                    return
        except:
            pass

        # Only flag extremely long URLs (>500 chars) as high risk
        # Many legitimate sites have long tracking/analytics URLs
        if L > 500:
            self._add_signal(
                results,
                "URL extremamente longa",
                severity="medium",
                weight=0.22,
            )
            results["details"]["url_length"] = L
        elif L > 300:
            self._add_signal(
                results,
                "URL muito longa",
                severity="low",
                weight=0.12,
            )
            results["details"]["url_length"] = L
        elif L > 100:
            results["details"]["url_length"] = L
            self._add_signal(
                results,
                "URL longa",
                severity="low",
                weight=0.12,
                include_summary=False,
            )

    # Multi-level public suffixes (minimal set to reduce false positives)
    MULTI_LEVEL_TLDS = {
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "edu.br",
        "co.uk",
        "com.au",
        "co.jp",
        "com.mx",
        "com.ar",
        "com.tr",
        "co.kr",
        "co.in",
    }

    def _get_sld(self, domain: str) -> str:
        """
        Registrable domain extraction with basic multi-level TLD support.
        For 'a.b.nubank.com.br' -> 'nubank.com.br'
        """
        host = domain.split(":")[0].lower()
        parts = host.split(".")
        if len(parts) < 2:
            return host
        suffix2 = ".".join(parts[-2:])
        if suffix2 in self.MULTI_LEVEL_TLDS and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def _levenshtein(self, a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i]
            for j, cb in enumerate(b, 1):
                ins = cur[j - 1] + 1
                dele = prev[j] + 1
                sub = prev[j - 1] + (ca != cb)
                cur.append(min(ins, dele, sub))
            prev = cur
        return prev[-1]

    def _check_brand_impersonation_and_similarity(self, domain: str, results: dict):
        d = domain.lower()
        sld = self._get_sld(d)
        sld_label = sld.split(".")[0] if "." in sld else sld

        # Direct substring impersonation
        for brand in self.COMMON_BRANDS:
            if brand in d:
                # Consider official domains as legitimate (avoid false positives)
                official_domains = {f"{brand}.com", f"{brand}.com.br"}
                # Per-brand allowlist to avoid false positives on official sites
                if brand == "nubank":
                    official_domains.update({"nubank.com.br", "nubank.com"})
                elif brand == "discord":
                    official_domains.update({"discord.com", "discordapp.com"})
                elif brand == "paypal":
                    official_domains.update({"paypal.com"})
                elif brand == "google":
                    official_domains.update(
                        {
                            "google.com",
                            "google.com.br",
                            "accounts.google.com",
                            "accounts.youtube.com",
                            "mail.google.com",
                            "youtube.com",
                            "gmail.com",
                            "goo.gl",
                            "youtu.be",
                        }
                    )
                elif brand == "facebook":
                    official_domains.update({"facebook.com"})
                elif brand == "microsoft":
                    official_domains.update(
                        {
                            "microsoft.com",
                            "microsoftonline.com",
                            "login.microsoftonline.com",
                            "login.live.com",
                            "login.windows.net",
                            "office.com",
                            "office365.com",
                            "live.com",
                            "outlook.com",
                            "outlook.live.com",
                        }
                    )
                elif brand == "apple":
                    official_domains.update(
                        {
                            "apple.com",
                            "appleid.apple.com",
                            "idmsa.apple.com",
                            "icloud.com",
                        }
                    )
                elif brand == "netflix":
                    official_domains.update({"netflix.com"})
                elif brand == "instagram":
                    official_domains.update({"instagram.com"})
                elif brand == "twitter":
                    official_domains.update({"twitter.com", "x.com", "t.co"})
                elif brand == "linkedin":
                    official_domains.update({"linkedin.com"})
                elif brand == "itau":
                    official_domains.update({"itau.com.br"})
                elif brand == "bradesco":
                    official_domains.update({"bradesco.com.br"})
                elif brand == "santander":
                    official_domains.update(
                        {"santander.com.br", "santander.com"})
                elif brand == "caixa":
                    official_domains.update({"caixa.gov.br"})
                elif brand == "inter":
                    official_domains.update({"bancointer.com.br", "inter.co"})
                elif brand == "whatsapp":
                    official_domains.update({"whatsapp.com"})
                elif brand == "outlook":
                    official_domains.update({"outlook.com", "live.com"})
                elif brand == "office":
                    official_domains.update({"office.com", "microsoft.com"})
                elif brand == "onedrive":
                    official_domains.update({"onedrive.live.com"})
                elif brand == "coinbase":
                    official_domains.update({"coinbase.com"})
                elif brand == "binance":
                    official_domains.update({"binance.com"})
                # Multi-level public suffixes expansion
                official_domains.update(
                    {f"{brand}.{sfx}" for sfx in self.MULTI_LEVEL_TLDS}
                )

                if sld not in official_domains:
                    self._add_signal(
                        results,
                        f"Possível imitação de marca: {brand}",
                        severity="high",
                        weight=0.42,
                    )
                    results["details"].setdefault("brand_impersonation", []).append(
                        brand
                    )
                    break

        # Similarity via Levenshtein (typosquatting): compare SLD label with brand
        # Only flag if distance is 1 AND the strings are similar enough in length
        best_match: Optional[Tuple[str, int]] = None
        for brand in self.COMMON_BRANDS:
            dist = self._levenshtein(sld_label, brand)
            if best_match is None or dist < best_match[1]:
                best_match = (brand, dist)

        # Only flag distance=1 (single typo) and require similar length to avoid false positives
        # Example: "lance" vs "banco" has distance=2, but they're unrelated words
        if best_match and best_match[1] == 1:
            # Require length similarity - within 2 characters
            brand_len = len(best_match[0])
            label_len = len(sld_label)
            if abs(brand_len - label_len) <= 2:
                self._add_signal(
                    results,
                    f"Semelhança com '{best_match[0]}' (distância de Levenshtein = {best_match[1]})",
                    severity="high",
                    weight=0.35,
                )
                results["details"]["levenshtein_similarity"] = {
                    "brand": best_match[0],
                    "distance": best_match[1],
                    "compared_label": sld_label,
                }

    def _check_dynamic_dns(self, domain: str, results: dict):
        base = self._get_sld(domain).lower()
        for suffix in self.DYNAMIC_DNS_SUFFIXES:
            if base.endswith(suffix):
                self._add_signal(
                    results,
                    "Uso de DNS dinâmico",
                    severity="high",
                    weight=0.4,
                )
                results["details"]["dynamic_dns"] = suffix
                return

    # ---------------------------
    # SSL Checks
    # ---------------------------
    def _check_ssl_certificate(self, domain: str, results: dict):
        host = domain.split(":")[0]
        try:
            ctx = ssl.create_default_context()
            # Reduce timeout even more for SSL checks
            with socket.create_connection((host, 443), timeout=1) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

            ssl_issues: List[str] = []
            # Hostname match
            if not self._cert_matches_hostname(cert, host):
                issue = "Certificado não corresponde ao domínio"
                ssl_issues.append(issue)
                self._add_signal(results, issue, severity="high", weight=0.34)

            # Expiration
            not_after = cert.get("notAfter")
            if not_after:
                # Example: 'Jun  1 12:00:00 2025 GMT'
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.now(timezone.utc)
                expires_utc = expires.replace(tzinfo=timezone.utc)
                delta_days = (expires_utc - now).days
                results["details"]["ssl_days_to_expire"] = delta_days

                if delta_days < 0:
                    issue = "Certificado expirado"
                    ssl_issues.append(issue)
                    self._add_signal(
                        results,
                        issue,
                        severity="critical",
                        weight=0.55,
                    )
                elif delta_days <= 14:
                    issue = "Certificado expirando em breve"
                    ssl_issues.append(issue)
                    self._add_signal(
                        results,
                        issue,
                        severity="medium",
                        weight=0.2,
                        include_summary=False,
                    )

            issuer = cert.get("issuer")
            subject = cert.get("subject")
            if issuer:
                results["details"]["ssl_issuer"] = " / ".join(
                    ["=".join(attr) for rdn in issuer for attr in rdn]
                )
            if subject:
                results["details"]["ssl_subject"] = " / ".join(
                    ["=".join(attr) for rdn in subject for attr in rdn]
                )

            if ssl_issues:
                results["details"]["ssl_issues"] = ssl_issues

        except Exception as e:
            # SSL fetch failed: could be HTTP-only site or TLS blocked; don't over-penalize
            msg = str(e)
            results["details"]["ssl_error"] = msg
            low = msg.lower()
            if (
                "nameresolutionerror" in low
                or "nodename nor servname provided" in low
                or "name or service not known" in low
            ):
                self._add_signal(
                    results,
                    "Falha na resolução DNS (SSL)",
                    severity="low",
                    weight=0.1,
                )

    def _cert_matches_hostname(self, cert, hostname: str) -> bool:
        """
        Robust hostname check using SANs and wildcard support.
        """
        try:
            ssl.match_hostname(cert, hostname)
            return True
        except Exception:
            san = cert.get("subjectAltName", [])
            dns_names = [v for (k, v) in san if k.lower() == "dns"]

            def _wildcard_match(name: str, host: str) -> bool:
                if name.startswith("*."):
                    suffix = name[1:]  # ".example.com"
                    return host.endswith(suffix) and host.count(".") >= suffix.count(
                        "."
                    )
                return name.lower() == host.lower()

            for name in dns_names:
                if _wildcard_match(name, hostname):
                    return True

            subject = cert.get("subject", [])
            cns = [
                val
                for rdn in subject
                for (key, val) in rdn
                if key.lower() == "commonname"
            ]
            for cn in cns:
                if _wildcard_match(cn, hostname):
                    return True
            return False

    # ---------------------------
    # WHOIS Checks
    # ---------------------------
    def _check_whois_age(self, domain: str, results: dict):
        try:
            age_days = self._get_domain_age_days(domain)
            if age_days is None:
                results["details"]["whois_age_days"] = None
                return

            results["details"]["whois_age_days"] = age_days
            if age_days < 30:
                self._add_signal(
                    results,
                    "Domínio muito novo (< 30 dias)",
                    severity="high",
                    weight=0.4,
                )
            elif age_days < 90:
                self._add_signal(
                    results,
                    "Domínio recente (< 90 dias)",
                    severity="medium",
                    weight=0.24,
                )
        except Exception as e:
            results["details"]["whois_error"] = str(e)

    def _get_domain_age_days(self, domain: str) -> Optional[int]:
        """
        Best-effort WHOIS lookup using IANA refer + specific whois server.
        Many TLDs have different registries; this may fail in some cases.

        Returns:
            int days or None if unknown.
        """
        sld = self._get_sld(domain)
        tld = sld.split(".")[-1]

        whois_server = self._query_iana_whois_server(tld)
        if not whois_server:
            # Try some defaults
            if tld in ("com", "net"):
                whois_server = "whois.verisign-grs.com"
            elif tld == "org":
                whois_server = "whois.pir.org"
            else:
                return None

        raw = self._raw_whois_query(whois_server, sld)
        if not raw:
            return None

        created = self._parse_whois_creation_date(raw)
        if not created:
            return None

        now = datetime.now(timezone.utc)
        delta = now - created
        return max(0, delta.days)

    def _query_iana_whois_server(self, tld: str) -> Optional[str]:
        try:
            resp = self._raw_whois_query("whois.iana.org", tld)
            if not resp:
                return None
            m = re.search(r"^whois:\s*(.+)$", resp,
                          re.MULTILINE | re.IGNORECASE)
            if m:
                return m.group(1).strip()
            return None
        except Exception:
            return None

    def _raw_whois_query(self, server: str, query: str) -> Optional[str]:
        try:
            with socket.create_connection((server, 43), timeout=1) as s:
                s.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
                s.shutdown(socket.SHUT_WR)
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            try:
                return data.decode("utf-8", errors="ignore")
            except Exception:
                return data.decode("latin1", errors="ignore")
        except Exception:
            return None

    def _parse_whois_creation_date(self, raw: str) -> Optional[datetime]:
        """
        Try common WHOIS labels and date formats.
        """
        patterns = [
            r"Creation Date:\s*(.+)",
            r"Created On:\s*(.+)",
            r"Domain Registration Date:\s*(.+)",
            r"created:\s*(.+)",
            r"Registered On:\s*(.+)",
        ]
        dt_formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%d-%b-%Y",
            "%Y.%m.%d %H:%M:%S",
        ]
        for pat in patterns:
            m = re.search(pat, raw, re.IGNORECASE)
            if not m:
                continue
            val = m.group(1).strip()
            # Trim trailing stuff
            val = val.split("  ")[0].strip()
            # Try multiple formats
            for fmt in dt_formats:
                try:
                    dt = datetime.strptime(val, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except Exception:
                    continue
            # Some registries include timezone abbreviations; last resort parse
            try:
                # Remove trailing TZ strings if any and retry
                val2 = re.sub(r"\s+[A-Z]{2,4}$", "", val)
                for fmt in dt_formats:
                    try:
                        dt = datetime.strptime(val2, fmt)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        return dt.astimezone(timezone.utc)
                    except Exception:
                        continue
            except Exception:
                pass
        return None

    # ---------------------------
    # Redirects + Content Scan
    # ---------------------------
    def _check_redirects_and_content(self, url: str, results: dict):
        headers = {"User-Agent": self.USER_AGENT}
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=1,
                allow_redirects=True,
            )
        except Exception as e:
            msg = str(e)
            results["details"]["http_error"] = msg
            lowered = msg.lower()
            # Mark DNS resolution failures as a minor suspicious feature
            if (
                "nameresolutionerror" in lowered
                or "nodename nor servname provided" in lowered
                or "name or service not known" in lowered
            ):
                self._add_signal(
                    results,
                    "Falha na resolução DNS",
                    severity="low",
                    weight=0.12,
                )
            return

        chain = [r.url for r in resp.history] + [resp.url]
        results["details"]["redirect_chain"] = chain

        # Redirect heuristics
        if len(resp.history) >= 3:
            issue = f"Número alto de redirecionamentos: {len(resp.history)}"
            self._add_signal(
                results,
                issue,
                severity="medium",
                weight=0.18,
            )
            results["details"].setdefault("redirect_issues", []).append(issue)

        orig_domain = self._extract_domain(urlparse(url)).lower()
        final_domain = self._extract_domain(urlparse(resp.url)).lower()
        if (
            orig_domain
            and final_domain
            and self._get_sld(orig_domain) != self._get_sld(final_domain)
        ):
            issue = "Redirecionamento para outro domínio"
            self._add_signal(
                results,
                issue,
                severity="medium",
                weight=0.22,
            )
            results["details"].setdefault("redirect_issues", []).append(issue)

        # Basic content analysis (only if HTML-ish)
        ctype = resp.headers.get("Content-Type", "")
        if (
            "text/html" in ctype
            or "application/xhtml" in ctype
            or resp.text.startswith("<")
        ):
            self._analyze_html_content(resp, results)
            # Analyze source code for malicious patterns and obfuscation
            self._analyze_source_code(resp, results)
            # Analyze for malicious SEO practices (keyword stuffing, cloaking, doorway pages)
            self._analyze_malicious_seo(resp, results)

    def _analyze_html_content(self, resp: requests.Response, results: dict):
        html = resp.text[:500_000]  # hard cap
        lowered = html.lower()

        # Find forms and password fields
        forms = len(re.findall(r"<\s*form\b", lowered))
        pwd_fields = len(re.findall(r"type\s*=\s*['\"]password['\"]", lowered))
        email_fields = len(re.findall(r"type\s*=\s*['\"]email['\"]", lowered))

        # Only look for sensitive keywords if there are forms with password fields
        # This reduces false positives on news sites and regular content
        sensitive_keywords = [
            "senha",
            "password",
            "ssn",
            "cpf",
            "cnpj",
            "cartão",
            "cartao",
            "cvv",
            "pin",
            "conta corrente",
            "verificar identidade",
            "verificação de conta",
            "verify account",
            "confirm identity",
            "2fa",
        ]
        found_kw = []
        # Only check keywords if page has password fields (likely a login form)
        if pwd_fields > 0:
            for kw in sensitive_keywords:
                # Use word-like boundaries to avoid matching substrings
                pattern = r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])"
                if re.search(pattern, lowered):
                    found_kw.append(kw)

        details = results["details"].setdefault("content_analysis", {})
        details["forms_found"] = forms
        details["password_fields"] = pwd_fields
        details["email_fields"] = email_fields
        if found_kw:
            details["keywords"] = found_kw

        # Heuristics scoring
        if pwd_fields > 0:
            details_snapshot = results.get("details", {})
            domain_age = details_snapshot.get("whois_age_days")
            suspicious_domain = bool(
                details_snapshot.get("suspicious_tld")
                or details_snapshot.get("dynamic_dns")
                or details_snapshot.get("ip_address")
            )

            severity = "medium"
            weight = 0.22
            if suspicious_domain or (domain_age is not None and domain_age < 120):
                severity = "high"
                weight = 0.36

            self._add_signal(
                results,
                "Página com campo de senha",
                severity=severity,
                weight=weight,
            )
        if forms > 3:
            self._add_signal(
                results,
                "Múltiplos formulários na página",
                severity="low",
                weight=0.08,
            )
        if found_kw and pwd_fields > 0:
            # Only flag sensitive content if there's also a password field
            self._add_signal(
                results,
                "Formulário solicita credenciais sensíveis",
                severity="medium",
                weight=0.18,
            )

        # Attempt to extract form action domains differing from current
        actions = re.findall(
            r"<\s*form[^>]*action\s*=\s*['\"]([^'^\"]+)['\"][^>]*>", lowered
        )
        external_actions: List[str] = []
        for action in actions:
            try:
                abs_url = urljoin(resp.url, action)
                action_domain = self._extract_domain(urlparse(abs_url)).lower()
                page_domain = self._extract_domain(urlparse(resp.url)).lower()
                if (
                    action_domain
                    and page_domain
                    and self._get_sld(action_domain) != self._get_sld(page_domain)
                ):
                    external_actions.append(abs_url)
            except Exception:
                continue

        if external_actions:
            details["external_form_actions"] = external_actions
            self._add_signal(
                results,
                "Formulário envia dados para domínio diferente",
                severity="medium",
                weight=0.25,
            )

    def _analyze_source_code(self, resp: requests.Response, results: dict):
        """
        Analyze HTML/JavaScript source code for malicious scripts,
        obfuscation techniques, and suspicious patterns.
        """
        html = resp.text[:500_000]  # hard cap

        try:
            code_analyzer = CodeAnalyzer()
            code_results = code_analyzer.analyze(html)

            # Store detailed code analysis results
            results["details"]["code_analysis"] = {
                "malicious_patterns_count": len(code_results["malicious_patterns"]),
                "obfuscation_count": len(code_results["obfuscation_detected"]),
                "exfiltration_risks_count": len(code_results["exfiltration_risks"]),
                "credential_risks_count": len(code_results["credential_risks"]),
                "suspicious_scripts_count": len(code_results["suspicious_scripts"]),
                "entropy": code_results["entropy_analysis"],
                "risk_level": code_results["risk_level"],
                "summary": code_results["summary"],
            }

            # Add detailed findings for transparency
            if code_results["malicious_patterns"]:
                results["details"]["code_analysis"]["malicious_patterns"] = [
                    {
                        "type": p["type"],
                        "description": p["description"],
                        "severity": p["severity"],
                        "count": p["count"],
                    }
                    # Limit to top 10
                    for p in code_results["malicious_patterns"][:10]
                ]

            if code_results["obfuscation_detected"]:
                results["details"]["code_analysis"]["obfuscation_techniques"] = [
                    {
                        "type": p["type"],
                        "description": p["description"],
                        "severity": p["severity"],
                        "count": p["count"],
                    }
                    for p in code_results["obfuscation_detected"][:10]
                ]

            if code_results["suspicious_scripts"]:
                results["details"]["code_analysis"]["suspicious_scripts"] = [
                    {
                        "script_id": s["script_id"],
                        "findings_count": len(s["findings"]),
                        "preview": s["preview"][:100],  # Shorter preview
                    }
                    for s in code_results["suspicious_scripts"][
                        :5
                    ]  # Limit to 5 scripts
                ]

            # Add signals based on code analysis findings
            # Critical findings
            critical_patterns = [
                p
                for p in code_results["malicious_patterns"]
                if p["severity"] == "critical"
            ]
            if critical_patterns:
                self._add_signal(
                    results,
                    f"Código malicioso crítico detectado ({len(critical_patterns)} padrões)",
                    severity="critical",
                    weight=0.5,
                )

            # High severity obfuscation
            high_obfuscation = [
                p
                for p in code_results["obfuscation_detected"]
                if p["severity"] in ["critical", "high"]
            ]
            if high_obfuscation:
                self._add_signal(
                    results,
                    f"Ofuscação de código detectada ({len(high_obfuscation)} técnicas)",
                    severity="high",
                    weight=0.35,
                )

            # Credential harvesting patterns
            if code_results["credential_risks"]:
                high_cred_risks = [
                    p
                    for p in code_results["credential_risks"]
                    if p["severity"] in ["high", "critical"]
                ]
                suspicious_context = self._has_suspicious_credential_context(
                    results)

                if high_cred_risks and suspicious_context:
                    self._add_signal(
                        results,
                        "Padrões de captura de credenciais detectados",
                        severity="high",
                        weight=0.38,
                    )
                elif len(high_cred_risks) > 1:
                    self._add_signal(
                        results,
                        "Múltiplos padrões de captura de credenciais detectados",
                        severity="medium",
                        weight=0.24,
                    )
                else:
                    medium_cred_risks = [
                        p
                        for p in code_results["credential_risks"]
                        if p["severity"] == "medium"
                    ]
                    if len(medium_cred_risks) >= 2 and suspicious_context:
                        self._add_signal(
                            results,
                            "Padrões de captura de credenciais detectados",
                            severity="medium",
                            weight=0.22,
                        )

            # High entropy (obfuscation indicator)
            if code_results["entropy_analysis"].get("is_suspicious"):
                max_entropy = code_results["entropy_analysis"].get(
                    "max_entropy", 0)
                if max_entropy >= 6.2:
                    self._add_signal(
                        results,
                        f"Alta entropia no código (entropia={max_entropy:.2f}) - possível ofuscação",
                        severity="high",
                        weight=0.32,
                    )
                elif max_entropy >= 5.6:
                    self._add_signal(
                        results,
                        f"Entropia elevada no código (entropia={max_entropy:.2f})",
                        severity="medium",
                        weight=0.18,
                    )

            # Multiple suspicious scripts
            if len(code_results["suspicious_scripts"]) >= 3:
                self._add_signal(
                    results,
                    f"Múltiplos scripts suspeitos ({len(code_results['suspicious_scripts'])})",
                    severity="medium",
                    weight=0.22,
                )

            # Data exfiltration risks
            high_exfil = []
            for p in code_results["exfiltration_risks"]:
                severity = p.get("severity")
                count = p.get("count", 0)
                if severity == "high" and count >= 2:
                    high_exfil.append(p)
                elif severity == "medium" and count >= 5:
                    high_exfil.append(p)
            if high_exfil:
                self._add_signal(
                    results,
                    "Múltiplas tentativas de exfiltração de dados detectadas",
                    severity="medium",
                    weight=0.25,
                )

        except Exception as e:
            # Don't fail the entire analysis if code analysis fails
            results["details"]["code_analysis"] = {
                "error": f"Erro na análise de código: {str(e)}"
            }

    def _analyze_malicious_seo(self, resp: requests.Response, results: dict) -> None:
        """
        Detect malicious SEO practices:
        - Keyword stuffing (excessive repetition of terms, hidden text blocks)
        - Cloaking (different content for bots vs users)
        - Doorway pages (link farms, meta-refresh with thin content)
        """
        try:
            html = resp.text[:500_000]
            lowered = html.lower()

            seo_details = results.setdefault(
                "details", {}).setdefault("seo_analysis", {})

            # -----------------------
            # Keyword stuffing
            # -----------------------
            # Remove scripts/styles/comments for visible text approximation
            cleaned = re.sub(r"<script[\s\S]*?</script>",
                             " ", lowered, flags=re.IGNORECASE)
            cleaned = re.sub(r"<style[\s\S]*?</style>",
                             " ", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"<!--([\s\S]*?)-->", " ", cleaned)
            # Strip tags
            visible_text = re.sub(r"<[^>]+>", " ", cleaned)

            # Tokenize words (support accents)
            tokens = re.findall(r"[a-zA-ZÀ-ÖØ-öø-ÿ]{2,}", visible_text)
            total_words = len(tokens)
            stopwords = {
                # PT & EN minimal list
                "a", "o", "os", "as", "de", "da", "do", "das", "dos", "e", "é", "em", "para", "por", "um", "uma", "ou", "que", "com", "na", "no", "nas", "nos", "se", "não", "sim", "the", "and", "of", "to", "in", "for", "on", "is", "it", "with", "as", "by", "at", "from", "this", "that", "or", "an", "be", "are", "was", "were"
            }
            tokens_wo_sw = [t for t in tokens if t not in stopwords]
            total_wo_sw = len(tokens_wo_sw)

            top_terms = []
            top_ratio = 0.0
            unique_ratio = 1.0
            repeated_runs = 0
            if total_wo_sw >= 50:
                freq = {}
                for t in tokens_wo_sw:
                    freq[t] = freq.get(t, 0) + 1
                # Top 5 terms
                top_terms = sorted(
                    freq.items(), key=lambda kv: kv[1], reverse=True)[:5]
                top_count = top_terms[0][1] if top_terms else 0
                top_ratio = (top_count / total_wo_sw) if total_wo_sw else 0.0
                unique_ratio = (
                    len(freq) / total_wo_sw) if total_wo_sw else 1.0
                # Repeated word runs like "comprar comprar comprar"
                repeated_runs = len(re.findall(
                    r"\b([a-zA-ZÀ-ÖØ-öø-ÿ]+)(?:\s+\1){2,}\b", visible_text, re.IGNORECASE))

            # meta keywords overflow
            meta_kw_matches = re.findall(
                r"<meta[^>]+name=[\"']keywords[\"'][^>]+content=[\"']([^\"']+)[\"'][^>]*>", lowered)
            meta_kw_len = 0
            if meta_kw_matches:
                meta_kw_len = sum(s.count(",") + 1 for s in meta_kw_matches)

            # Hidden text blocks with long content
            hidden_blocks = re.findall(
                r"<([a-z0-9]+)[^>]*style=[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^\"']*[\"'][^>]*>([\s\S]*?)</\1>", html, re.IGNORECASE)
            long_hidden_count = 0
            for _, _, inner in hidden_blocks[:50]:  # cap
                # Count words inside hidden blocks
                inner_tokens = re.findall(r"[a-zA-ZÀ-ÖØ-öø-ÿ]{2,}", inner)
                if len(inner_tokens) >= 30:
                    long_hidden_count += 1

            stuffing_signals = 0
            if total_wo_sw >= 100 and top_ratio >= 0.07 and (top_terms and top_terms[0][1] >= 50):
                stuffing_signals += 1
            if total_wo_sw >= 150 and sum(c for _, c in top_terms[:3]) / total_wo_sw >= 0.18:
                stuffing_signals += 1
            if unique_ratio <= 0.2:
                stuffing_signals += 1
            if repeated_runs >= 2:
                stuffing_signals += 1
            if meta_kw_len >= 20:
                stuffing_signals += 1
            if long_hidden_count >= 2:
                stuffing_signals += 1

            if stuffing_signals >= 2:
                severity = "medium"
                weight = 0.22
                if stuffing_signals >= 4:
                    severity = "high"
                    weight = 0.35
                self._add_signal(
                    results,
                    "Possível keyword stuffing (SEO malicioso)",
                    severity=severity,
                    weight=weight,
                )
                seo_details["keyword_stuffing"] = {
                    "total_words_no_stopwords": total_wo_sw,
                    "top_terms": top_terms,
                    "top_ratio": round(top_ratio, 3),
                    "unique_ratio": round(unique_ratio, 3),
                    "repeated_runs": repeated_runs,
                    "meta_keywords_count": meta_kw_len,
                    "hidden_blocks_long": long_hidden_count,
                }

            # -----------------------
            # Doorway pages
            # -----------------------
            anchors = re.findall(
                r"<a\s[^>]*href\s*=\s*[\"']([^\"']+)[\"']", lowered)
            anchor_count = len(anchors)
            # Estimate word count (visible)
            word_count = total_words

            external_count = 0
            same_count = 0
            try:
                page_domain = self._extract_domain(urlparse(resp.url)).lower()
                page_sld = self._get_sld(page_domain) if page_domain else ""
                for href in anchors[:1000]:  # cap
                    try:
                        abs_url = urljoin(resp.url, href)
                        ad = self._extract_domain(urlparse(abs_url)).lower()
                        if not ad:
                            continue
                        if page_sld and self._get_sld(ad) != page_sld:
                            external_count += 1
                        else:
                            same_count += 1
                    except Exception:
                        continue
            except Exception:
                pass

            external_ratio = (
                external_count / anchor_count) if anchor_count else 0.0

            # Meta refresh fast redirects
            meta_refresh = re.findall(
                r"<meta[^>]+http-equiv=[\"']refresh[\"'][^>]+content=[\"']\s*(\d+)\s*;\s*url=", lowered)
            fast_refresh = [int(s)
                            for s in meta_refresh if s.isdigit() and int(s) <= 3]

            doorway_signals = 0
            if anchor_count >= 100 and word_count < 300 and external_ratio >= 0.7:
                doorway_signals += 1
            if fast_refresh:
                doorway_signals += 1

            if doorway_signals >= 1:
                self._add_signal(
                    results,
                    "Padrões de doorway page (SEO malicioso)",
                    severity="medium",
                    weight=0.22,
                )
                seo_details["doorway_page"] = {
                    "anchors": anchor_count,
                    "external_links": external_count,
                    "internal_links": same_count,
                    "external_ratio": round(external_ratio, 2),
                    "word_count": word_count,
                    "fast_meta_refresh": len(fast_refresh),
                }

            # -----------------------
            # Cloaking (bot vs user content)
            # -----------------------
            try:
                bot_headers = {
                    "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
                bot_resp = requests.get(
                    resp.url,
                    headers=bot_headers,
                    timeout=1,
                    allow_redirects=True,
                )
                bot_html = bot_resp.text[:200_000].lower()

                # Normalize: strip tags/scripts/styles/comments
                def _norm(txt: str) -> str:
                    t = re.sub(r"<script[\s\S]*?</script>",
                               " ", txt, flags=re.IGNORECASE)
                    t = re.sub(r"<style[\s\S]*?</style>",
                               " ", t, flags=re.IGNORECASE)
                    t = re.sub(r"<!--([\s\S]*?)-->", " ", t)
                    t = re.sub(r"<[^>]+>", " ", t)
                    t = re.sub(r"\s+", " ", t)
                    return t.strip()

                user_norm = _norm(lowered)
                bot_norm = _norm(bot_html)

                # Token sets for Jaccard similarity (top 200 tokens)
                def _top_tokens(txt: str):
                    toks = re.findall(r"[a-zA-ZÀ-ÖØ-öø-ÿ]{3,}", txt)
                    counts = {}
                    for t in toks:
                        counts[t] = counts.get(t, 0) + 1
                    items = sorted(
                        counts.items(), key=lambda kv: kv[1], reverse=True)[:200]
                    return {w for w, _ in items}

                set_user = _top_tokens(user_norm)
                set_bot = _top_tokens(bot_norm)
                union = len(set_user | set_bot)
                inter = len(set_user & set_bot)
                jaccard = (inter / union) if union else 1.0

                len_u = max(1, len(user_norm))
                len_b = max(1, len(bot_norm))
                len_diff = abs(len_u - len_b) / max(len_u, len_b)

                # Compare final redirect targets as well
                try:
                    orig_domain = self._get_sld(
                        self._extract_domain(urlparse(resp.url)).lower())
                    bot_domain = self._get_sld(
                        self._extract_domain(urlparse(bot_resp.url)).lower())
                except Exception:
                    orig_domain = bot_domain = ""

                different_redirect = bool(
                    orig_domain and bot_domain and orig_domain != bot_domain)

                if (jaccard < 0.35 and len_diff > 0.4) or different_redirect:
                    self._add_signal(
                        results,
                        "Possível cloaking (conteúdo para bot difere do usuário)",
                        severity="high",
                        weight=0.34,
                    )
                    seo_details["cloaking"] = {
                        "jaccard": round(jaccard, 2),
                        "length_diff": round(len_diff, 2),
                        "user_final_url": resp.url,
                        "bot_final_url": bot_resp.url,
                        "different_redirect_domain": different_redirect,
                    }
            except Exception:
                # Ignore cloaking check failures silently
                pass

        except Exception as e:
            results.setdefault("details", {}).setdefault(
                "seo_analysis", {})["error"] = str(e)

    # ---------------------------
    # Utilities
    # ---------------------------
    def _has_suspicious_credential_context(self, results: dict) -> bool:
        details = results.get("details", {})
        content_details = details.get("content_analysis", {})

        domain_age = details.get("whois_age_days")
        has_external_form = bool(content_details.get("external_form_actions"))

        suspicious_domain = bool(
            details.get("suspicious_tld")
            or details.get("dynamic_dns")
            or details.get("ip_address")
        )

        existing_high = any(
            comp.get("severity") in {"high", "critical"}
            for comp in details.get("score_breakdown", [])
        )

        is_new_domain = domain_age is not None and domain_age < 120

        return has_external_form or suspicious_domain or existing_high or is_new_domain

    def _extract_domain(self, parsed: urlparse) -> str:
        host = parsed.netloc or ""
        host = host.strip().lower()
        if host.startswith("www."):
            host = host[4:]
        return host.split("@")[-1]  # strip userinfo if any
