import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests


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
        "banco",
        "bradesco",
        "itau",
        "santander",
        "caixa",
        "nubank",
        "inter",
        "whatsapp",
        "outlook",
        "office",
        "oneDrive".lower(),
        "coinbase",
        "binance",
    ]

    USER_AGENT: str = "PyPhish/1.0 (+https://example.local)"

    SCORE_WEIGHTS: dict[str, float] = {
        "low": 0.12,
        "medium": 0.22,
        "high": 0.4,
        "critical": 0.55,
    }

    def __init__(self, http_timeout: int = 8, tcp_timeout: int = 6):
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
            self._add_signal(results, "URL inválida", severity="critical", weight=1.0)
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

        # SSL certificate
        self._check_ssl_certificate(domain, results)

        # WHOIS age
        self._check_whois_age(domain, results)

        # redirects + basic content scan
        self._check_redirects_and_content(url, results)

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
            weight = self.SCORE_WEIGHTS.get(severity, self.SCORE_WEIGHTS["low"])

        breakdown = results.setdefault("details", {}).setdefault("score_breakdown", [])
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
        if L > 300:
            self._add_signal(
                results,
                "URL extremamente longa",
                severity="high",
                weight=0.42,
            )
            results["details"]["url_length"] = L
        elif L > 200:
            self._add_signal(
                results,
                "URL muito longa",
                severity="medium",
                weight=0.26,
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
                    official_domains.update({"google.com", "google.com.br"})
                elif brand == "facebook":
                    official_domains.update({"facebook.com"})
                elif brand == "microsoft":
                    official_domains.update({"microsoft.com"})
                elif brand == "apple":
                    official_domains.update({"apple.com"})
                elif brand == "netflix":
                    official_domains.update({"netflix.com"})
                elif brand == "instagram":
                    official_domains.update({"instagram.com"})
                elif brand == "twitter":
                    official_domains.update({"twitter.com", "x.com"})
                elif brand == "linkedin":
                    official_domains.update({"linkedin.com"})
                elif brand == "itau":
                    official_domains.update({"itau.com.br"})
                elif brand == "bradesco":
                    official_domains.update({"bradesco.com.br"})
                elif brand == "santander":
                    official_domains.update({"santander.com.br", "santander.com"})
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
        best_match: Optional[Tuple[str, int]] = None
        for brand in self.COMMON_BRANDS:
            dist = self._levenshtein(sld_label, brand)
            if best_match is None or dist < best_match[1]:
                best_match = (brand, dist)

        if best_match and best_match[1] in (1, 2):
            self._add_signal(
                results,
                f"Semelhança com '{best_match[0]}' (distância de Levenshtein = {best_match[1]})",
                severity="critical",
                weight=0.5,
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
            with socket.create_connection(
                (host, 443), timeout=self.tcp_timeout
            ) as sock:
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
            m = re.search(r"^whois:\s*(.+)$", resp, re.MULTILINE | re.IGNORECASE)
            if m:
                return m.group(1).strip()
            return None
        except Exception:
            return None

    def _raw_whois_query(self, server: str, query: str) -> Optional[str]:
        try:
            with socket.create_connection((server, 43), timeout=self.tcp_timeout) as s:
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
                timeout=self.http_timeout,
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

    def _analyze_html_content(self, resp: requests.Response, results: dict):
        html = resp.text[:500_000]  # hard cap
        lowered = html.lower()

        # Find forms and password fields
        forms = len(re.findall(r"<\s*form\b", lowered))
        pwd_fields = len(re.findall(r"type\s*=\s*['\"]password['\"]", lowered))
        email_fields = len(re.findall(r"type\s*=\s*['\"]email['\"]", lowered))

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
            "bank",
            "conta",
            "login",
            "verificar",
            "verificação",
            "verify",
            "2fa",
        ]
        found_kw = []
        for kw in sensitive_keywords:
            # Use word-like boundaries to avoid matching substrings inside brand names
            pattern = r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])"
            if re.search(pattern, lowered):
                # Avoid 'bank' hit solely because of 'nubank'
                if kw == "bank" and "nubank" in lowered:
                    continue
                found_kw.append(kw)

        details = results["details"].setdefault("content_analysis", {})
        details["forms_found"] = forms
        details["password_fields"] = pwd_fields
        details["email_fields"] = email_fields
        if found_kw:
            details["keywords"] = found_kw

        # Heuristics scoring
        if pwd_fields > 0:
            self._add_signal(
                results,
                "Página com campo de senha",
                severity="high",
                weight=0.36,
            )
        if forms > 2:
            self._add_signal(
                results,
                "Múltiplos formulários na página",
                severity="low",
                weight=0.12,
            )
        if found_kw:
            self._add_signal(
                results,
                "Conteúdo solicita informações sensíveis",
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

    # ---------------------------
    # Utilities
    # ---------------------------
    def _extract_domain(self, parsed: urlparse) -> str:
        host = parsed.netloc or ""
        host = host.strip().lower()
        if host.startswith("www."):
            host = host[4:]
        return host.split("@")[-1]  # strip userinfo if any
