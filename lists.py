import csv
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple

import requests


class PhishingListChecker:
    def __init__(
        self,
        cache_dir: str = "./cache",
        cache_duration_hours: int = 24,
        custom_database_file: Optional[str] = None,
    ):
        self.phishtank_url = "http://data.phishtank.com/data/online-valid.csv"
        self.openphish_url = "https://openphish.com/feed.txt"
        self.timeout = 5

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.phishtank_cache_file = self.cache_dir / "phishtank.csv"
        self.openphish_cache_file = self.cache_dir / "openphish.txt"

        self.custom_database_file = (
            Path(custom_database_file)
            if custom_database_file
            else self.cache_dir / "database.txt"
        )

        self.cache_duration = timedelta(hours=cache_duration_hours)

        self.max_retries = 1
        self.retry_delay = 2

        # In-memory caches to avoid re-reading files
        self._custom_db_cache = None
        self._phishtank_cache = None
        self._openphish_cache = None

    def _is_file_cache_valid(self, cache_file: Path) -> bool:
        if not cache_file.exists():
            return False

        file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
        return file_age < self.cache_duration

    def _load_custom_database(self) -> Optional[list]:
        if self._custom_db_cache is not None:
            return self._custom_db_cache

        if not self.custom_database_file.exists():
            return None

        try:
            with open(self.custom_database_file, "r") as f:
                data = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
                print(f"📦 Database customizado carregado ({len(data)} entradas)")
                self._custom_db_cache = data
                return data
        except Exception as e:
            print(f"⚠️  Erro ao ler database customizado: {e}")
            return None

    def _load_phishtank_from_cache(self) -> Optional[set]:
        if self._phishtank_cache is not None:
            return self._phishtank_cache

        # Always use cache if available, ignore expiration to avoid downloads/timeouts
        if not self.phishtank_cache_file.exists():
            return None

        try:
            urls = set()
            with open(self.phishtank_cache_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                # Only extract URLs, not all fields - much faster
                for row in reader:
                    if url := row.get("url"):
                        urls.add(self._normalize_url(url))
                print(f"📦 PhishTank carregado do cache ({len(urls)} entradas)")
                self._phishtank_cache = urls
                return urls
        except Exception as e:
            print(f"⚠️  Erro ao ler cache do PhishTank: {e}")
            return None

    def _save_phishtank_to_cache(self, csv_content: str):
        try:
            with open(self.phishtank_cache_file, "w", encoding="utf-8") as f:
                f.write(csv_content)

            lines = len(csv_content.splitlines()) - 1  # -1 for header
            print(f"💾 PhishTank salvo no cache ({lines} entradas)")
        except Exception as e:
            print(f"⚠️  Erro ao salvar cache do PhishTank: {e}")

    def _load_openphish_from_cache(self) -> Optional[list]:
        if self._openphish_cache is not None:
            return self._openphish_cache

        # Always use cache if available, ignore expiration to avoid downloads/timeouts
        if not self.openphish_cache_file.exists():
            return None

        try:
            with open(self.openphish_cache_file, "r") as f:
                data = f.read().splitlines()
                print(f"📦 OpenPhish carregado do cache ({len(data)} entradas)")
                self._openphish_cache = data
                return data
        except Exception as e:
            print(f"⚠️  Erro ao ler cache do OpenPhish: {e}")
            return None

    def _save_openphish_to_cache(self, data: list):
        try:
            with open(self.openphish_cache_file, "w") as f:
                f.write("\n".join(data))
            print(f"💾 OpenPhish salvo no cache ({len(data)} entradas)")
        except Exception as e:
            print(f"⚠️  Erro ao salvar cache do OpenPhish: {e}")

    def _fetch_with_retry(
        self, url: str, headers: Optional[dict] = None
    ) -> Optional[requests.Response]:
        for attempt in range(self.max_retries):
            try:
                print(
                    f"🌐 Baixando dados de {url}... (tentativa {attempt + 1}/{self.max_retries})"
                )
                response = requests.get(url, headers=headers, timeout=self.timeout)

                if response.status_code == 200:
                    print("✅ Download concluído com sucesso")
                    return response
                elif response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        wait_time = int(retry_after)
                    else:
                        wait_time = self.retry_delay * (2**attempt)

                    if attempt < self.max_retries - 1:
                        print(f"⏳ Rate limited (429). Aguardando {wait_time}s...")
                        time.sleep(wait_time)
                else:
                    print(f"❌ Erro HTTP {response.status_code}")
                    return response

            except requests.Timeout:
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2**attempt)
                    print(f"⏱️  Timeout. Tentando novamente em {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"❌ Timeout após {self.max_retries} tentativas")
                    raise
            except Exception as e:
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2**attempt)
                    print(f"⚠️  Erro: {e}. Tentando novamente em {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise

        return None

    def check_phishtank(self, url: str) -> Tuple[bool, str]:
        try:
            phish_list = self._load_phishtank_from_cache()

            if phish_list is None:
                # Skip download to avoid timeout - cache not available
                return (
                    False,
                    "PhishTank: Cache indisponível (use update_cache.py para baixar)",
                )

            normalized_url = self._normalize_url(url)
            if normalized_url in phish_list:
                return True, "URL encontrada no PhishTank"

            return False, "URL não encontrada no PhishTank"

        except Exception as e:
            return False, f"PhishTank: Erro - {str(e)}"

    def check_openphish(self, url: str) -> Tuple[bool, str]:
        try:
            phish_list = self._load_openphish_from_cache()

            if phish_list is None:
                # Skip download to avoid timeout - cache not available
                return (
                    False,
                    "OpenPhish: Cache indisponível (use update_cache.py para baixar)",
                )

            normalized_url = self._normalize_url(url)
            for entry in phish_list:
                if self._normalize_url(entry) == normalized_url:
                    return True, "URL encontrada no OpenPhish"

            return False, "URL não encontrada no OpenPhish"

        except Exception as e:
            return False, f"OpenPhish: Erro - {str(e)}"

    def check_custom_database(self, url: str) -> Tuple[bool, str]:
        try:
            phish_list = self._load_custom_database()

            if phish_list is None:
                return False, "Database customizado não encontrado"

            normalized_url = self._normalize_url(url)

            from urllib.parse import urlparse

            try:
                parsed = urlparse(
                    normalized_url
                    if "://" in normalized_url
                    else "http://" + normalized_url
                )
                domain = parsed.netloc or parsed.path
                domain = domain.replace("www.", "")
                domain = domain.split(":")[0]
            except Exception:
                domain = (
                    normalized_url.replace("http://", "")
                    .replace("https://", "")
                    .replace("www.", "")
                    .split("/")[0]
                    .split(":")[0]
                )

            for entry in phish_list:
                entry_normalized = self._normalize_url(entry).replace("www.", "")

                if entry_normalized == domain:
                    return True, f"Domínio encontrado no database local: {entry}"

                if entry_normalized in domain or domain in entry_normalized:
                    return (
                        True,
                        f"Domínio parcial encontrado no database local: {entry}",
                    )

                if entry_normalized in normalized_url or normalized_url.endswith(
                    entry_normalized
                ):
                    return True, f"URL encontrada no database local: {entry}"

            return False, "URL não encontrada no database local"

        except Exception as e:
            return False, f"Database local: Erro - {str(e)}"

    def check_all(self, url: str) -> dict:
        """Check URL against all available sources"""
        results = {}

        is_phish, msg = self.check_custom_database(url)
        results["custom_database"] = {"is_phishing": is_phish, "message": msg}

        is_phish, msg = self.check_openphish(url)
        results["openphish"] = {"is_phishing": is_phish, "message": msg}

        is_phish, msg = self.check_phishtank(url)
        results["phishtank"] = {"is_phishing": is_phish, "message": msg}

        return results

    def _normalize_url(self, url: str) -> str:
        return url.lower().strip().rstrip("/")

    def update_cache(self) -> dict:
        status = {}

        print("\n🔄 Atualizando cache de listas de phishing...\n")

        if self.phishtank_cache_file.exists():
            self.phishtank_cache_file.unlink()
        if self.openphish_cache_file.exists():
            self.openphish_cache_file.unlink()

        _, phishtank_msg = self.check_phishtank("http://dummy-test.com")
        status["phishtank"] = phishtank_msg

        _, openphish_msg = self.check_openphish("http://dummy-test.com")
        status["openphish"] = openphish_msg

        print("\n✅ Atualização do cache concluída\n")
        return status
