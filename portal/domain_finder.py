#!/usr/bin/env python3
"""
Expired / Expiring Domain Finder
---------------------------------
Helps find aged, categorized domains with good backlink profiles
for red team domain acquisition. Scrapes expireddomains.net, checks
WHOIS data, queries the Wayback Machine, and scores domains for
operational fitness.
"""

import re
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Conditional imports — not every operator will have all libs installed
# ---------------------------------------------------------------------------

_REQUESTS_AVAILABLE = False
_BS4_AVAILABLE = False
_WHOIS_AVAILABLE = False

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    pass

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    pass

try:
    import whois
    _WHOIS_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.expireddomains.net/",
}

_TLD_SCORES = {
    "com": 15,
    "net": 12,
    "org": 12,
    "io": 10,
    "co": 8,
}

# Numeric TLD IDs used by member.expireddomains.net POST filter form
_TLD_IDS = {
    "com": "2",
    "net": "3",
    "org": "4",
    "biz": "7",
    "info": "12",
    "eu":  "5",
    "co":  "69",
    "io":  "125",
    "ai":  "26",
    "me":  "268",
    "xyz": "465",
    "app": "834",
    "us":  "249",
    "uk":  "247",
    "de":  "1",
}

# Regex patterns for human-readable domain detection
_VOWELS = set("aeiou")
_CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

def is_human_readable(name):
    """Check if a domain label looks like a real word/name (not random chars).

    Checks consonant-vowel patterns, repeated chars, and pronounceability.
    Returns True if the name appears human-readable.
    """
    name = name.lower().split(".")[0]  # Get just the label
    if len(name) < 3:
        return False
    if len(name) > 25:
        return False

    # Check for excessive numbers
    digit_count = sum(1 for c in name if c.isdigit())
    if digit_count > len(name) * 0.3:
        return False

    # Check for excessive consecutive consonants (max 4)
    consonant_streak = 0
    max_consonant_streak = 0
    for ch in name:
        if ch in _CONSONANTS:
            consonant_streak += 1
            max_consonant_streak = max(max_consonant_streak, consonant_streak)
        else:
            consonant_streak = 0
    if max_consonant_streak > 4:
        return False

    # Check vowel ratio - real words have ~30-60% vowels
    alpha_chars = [c for c in name if c.isalpha()]
    if not alpha_chars:
        return False
    vowel_ratio = sum(1 for c in alpha_chars if c in _VOWELS) / len(alpha_chars)
    if vowel_ratio < 0.15 or vowel_ratio > 0.75:
        return False

    # Check for repeated characters (e.g. "xxxx")
    for i in range(len(name) - 2):
        if name[i] == name[i+1] == name[i+2]:
            return False

    return True

# Category to keyword mappings for targeted domain search
CATEGORY_KEYWORDS = {
    "technology": ["tech", "soft", "digital", "cloud", "cyber", "data", "app", "web", "code", "dev"],
    "consulting": ["consult", "advisor", "group", "partners", "solutions", "strategy", "management"],
    "finance": ["financial", "capital", "wealth", "invest", "fund", "asset", "banking", "fiscal"],
    "healthcare": ["health", "medical", "care", "clinic", "wellness", "pharma", "bio", "med"],
    "education": ["learn", "academy", "institute", "school", "study", "edu", "training", "course"],
    "news": ["news", "daily", "times", "journal", "media", "press", "report", "herald"],
    "marketing": ["marketing", "creative", "agency", "brand", "media", "design", "digital", "spark"],
    "ecommerce": ["shop", "store", "market", "goods", "trade", "buy", "retail", "commerce"],
    "travel": ["travel", "resort", "hotel", "tour", "vacation", "holiday", "lodge", "destination"],
}


# ===================================================================
# DomainFinder class
# ===================================================================

class DomainFinder:
    """Search, score, and filter expired / deleted domains."""

    _LOGIN_URL      = "https://www.expireddomains.net/login/"
    _LOGINCHECK_URL = "https://www.expireddomains.net/logincheck/"
    _BASE_URL       = "https://www.expireddomains.net"
    _MEMBER_BASE_URL = "https://member.expireddomains.net"
    _SEARCH_URL     = "https://member.expireddomains.net/domains/combinedexpired/"
    _ALT_SEARCH_URL = "https://www.expireddomains.net/domains/combinedexpired/"
    _LOGIN_HOSTS = (
        "https://member.expireddomains.net",
        "https://www.expireddomains.net",
        "https://member.expireddomains.com",
        "https://www.expireddomains.com",
    )
    _SEARCH_HOSTS = (
        "https://member.expireddomains.net",
        "https://www.expireddomains.net",
        "https://member.expireddomains.com",
        "https://www.expireddomains.com",
    )

    def __init__(self):
        """Initialise with default search parameters."""
        self.session = None
        self._logged_in = False
        self._search_url = self._SEARCH_URL
        self.last_error = ""
        self.last_info = {}
        if _REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update(_DEFAULT_HEADERS)

    # ------------------------------------------------------------------
    # Static helper — let callers know what's available
    # ------------------------------------------------------------------

    @staticmethod
    def is_available():
        """Return *True* if all required libraries are importable."""
        return _REQUESTS_AVAILABLE and _BS4_AVAILABLE and _WHOIS_AVAILABLE

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _auth_fail(self, message, **details):
        self._logged_in = False
        self.last_error = message
        self.last_info = details or {}
        return False

    def _search_candidates(self):
        urls = []
        for host in self._SEARCH_HOSTS:
            base = (host or "").rstrip("/")
            if not base:
                continue
            candidate = f"{base}/domains/combinedexpired/"
            if candidate not in urls:
                urls.append(candidate)
        for candidate in (self._SEARCH_URL, self._ALT_SEARCH_URL):
            if candidate and candidate not in urls:
                urls.append(candidate)
        return urls

    def _pick_search_url(self, preferred=None):
        candidates = []
        if preferred:
            candidates.append(preferred)
        candidates.extend([u for u in self._search_candidates() if u != preferred])

        for url in candidates:
            try:
                resp = self.session.get(url, timeout=20, allow_redirects=True)
            except Exception:
                continue
            body = (resp.text or "").lower()
            final_url = (resp.url or "").lower()
            if "captcha" in body:
                continue
            if "/login/" in final_url or "/logincheck/" in final_url:
                continue
            if "please login" in body or "you must be logged in" in body:
                continue
            self._search_url = url
            return True
        return False

    def login(self, username, password):
        """Authenticate with expireddomains.net.

        Returns True on success, False on failure. Tries both direct member
        login flow (as used by domainhunter) and logincheck SSO flow.
        """
        if not _REQUESTS_AVAILABLE or not _BS4_AVAILABLE:
            return self._auth_fail("requests and/or bs4 not installed")
        if not username or not password:
            return self._auth_fail("Missing expireddomains credentials")

        self.last_error = ""
        self.last_info = {}

        try:
            # Strategy 1: direct login POST to /login/ (domainhunter-style)
            for host in self._LOGIN_HOSTS:
                base = host.rstrip("/")
                login_url = f"{base}/login/"
                preferred_search = f"{base}/domains/combinedexpired/"
                payload = {
                    "login": username,
                    "password": password,
                    "redirect_2_url": "/begin",
                }
                try:
                    self.session.cookies.clear()
                    resp = self.session.post(
                        login_url,
                        data=payload,
                        headers={
                            "Referer": login_url,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        timeout=25,
                        allow_redirects=False,
                    )
                except Exception:
                    continue

                body = (resp.text or "").lower()
                location = (resp.headers.get("Location") or "").lower()
                cookies = self.session.cookies.get_dict()
                has_expired_cookie = "ExpiredDomainssessid" in cookies
                has_session_cookie = has_expired_cookie or any("sess" in str(k).lower() for k in cookies.keys())
                redirected_away = bool(location) and "/login/" not in location and "/logincheck/" not in location

                if "captcha" in body:
                    continue
                if has_session_cookie and (redirected_away or resp.status_code in (301, 302, 303)):
                    self._logged_in = True
                    self._search_url = preferred_search
                    self._pick_search_url(preferred_search)
                    self.last_info = {
                        "strategy": "direct_login",
                        "host": base,
                        "search_url": self._search_url,
                        "cookies": sorted(cookies.keys()),
                    }
                    return True

            # Strategy 2: logincheck flow, preserving hidden fields
            for host in self._LOGIN_HOSTS:
                base = host.rstrip("/")
                login_url = f"{base}/login/"
                logincheck_url = f"{base}/logincheck/"
                preferred_search = f"{base}/domains/combinedexpired/"
                try:
                    self.session.cookies.clear()
                    login_page = self.session.get(login_url, timeout=20)
                except Exception:
                    continue
                if login_page.status_code != 200:
                    continue

                payload = {}
                try:
                    soup = BeautifulSoup(login_page.text, "html.parser")
                    form = soup.find("form", action=re.compile(r"logincheck", re.I)) or soup.find("form")
                    if form:
                        for inp in form.find_all("input"):
                            name = (inp.get("name") or "").strip()
                            if not name:
                                continue
                            payload[name] = inp.get("value", "")
                except Exception:
                    payload = {}
                payload["login"] = username
                payload["password"] = password
                payload.setdefault("redirect_2_url", "/")

                try:
                    resp = self.session.post(
                        logincheck_url,
                        data=payload,
                        headers={
                            "Referer": login_url,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        timeout=25,
                        allow_redirects=True,
                    )
                except Exception:
                    continue

                body = (resp.text or "").lower()
                final_url = (resp.url or "").lower()
                cookies = self.session.cookies.get_dict()
                has_expired_cookie = "ExpiredDomainssessid" in cookies
                has_session_cookie = has_expired_cookie or any("sess" in str(k).lower() for k in cookies.keys())

                invalid_markers = (
                    "invalid login",
                    "login data is incorrect",
                    "username or password is wrong",
                    "password is wrong",
                    "wrong password",
                )
                if any(m in body for m in invalid_markers):
                    return self._auth_fail("ExpiredDomains credentials were rejected", host=base)
                if "captcha" in body:
                    continue
                if has_session_cookie and "/login/" not in final_url and "/logincheck/" not in final_url:
                    self._logged_in = True
                    self._search_url = preferred_search
                    self._pick_search_url(preferred_search)
                    self.last_info = {
                        "strategy": "logincheck",
                        "host": base,
                        "search_url": self._search_url,
                        "cookies": sorted(cookies.keys()),
                    }
                    return True

            return self._auth_fail(
                "Unable to establish authenticated ExpiredDomains session",
                hosts_tried=list(self._LOGIN_HOSTS),
            )
        except Exception:
            return self._auth_fail("Unexpected error during ExpiredDomains login")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_int(value, default=0):
        """Coerce *value* to int, falling back to *default*.

        Handles commas ("10,561,035"), M/K suffixes ("10.6 M" -> 10600000),
        and mixed text ("10.6 MMajestic.com" -> 10600000).
        """
        if value is None:
            return default
        s = str(value).strip()
        # Plain number with optional commas
        try:
            return int(s.replace(",", ""))
        except (ValueError, TypeError):
            pass
        # M (millions) or K (thousands) suffix — e.g. "10.6 M" or "1.2K"
        m = re.match(r'^([\d.]+)\s*([MK])', s, re.IGNORECASE)
        if m:
            try:
                num = float(m.group(1))
                multiplier = 1_000_000 if m.group(2).upper() == "M" else 1_000
                return int(num * multiplier)
            except (ValueError, TypeError):
                pass
        # Extract first integer from mixed text
        m = re.search(r'(\d+)', s)
        if m:
            try:
                return int(m.group(1))
            except (ValueError, TypeError):
                pass
        return default

    def _fetch_page(self, url, params=None):
        """Fetch a URL and return a BeautifulSoup tree (or *None*)."""
        if not _REQUESTS_AVAILABLE or not _BS4_AVAILABLE:
            return None
        try:
            resp = self.session.get(url, params=params, timeout=20)
            if resp.status_code != 200:
                return None
            return BeautifulSoup(resp.text, "html.parser")
        except requests.RequestException:
            return None

    @staticmethod
    def _parse_archive_age(text):
        """Parse an archive birth year or age value to age in years.

        The member portal shows ABY as a calendar year (e.g. '2009').
        Detect which form we have and return age in whole years.
        """
        if not text:
            return 0
        text = text.strip()
        m = re.search(r"(\d{4})", text)
        if m:
            year = int(m.group(1))
            current_year = datetime.now().year
            if 1990 <= year <= current_year + 1:
                return max(0, current_year - year)
        # Fallback: treat as a raw age number
        m = re.search(r"(\d+)", text)
        return int(m.group(1)) if m else 0

    def _parse_column_map(self, table):
        """Return a dict mapping metric keys to column indices.

        Inspects the <thead> (or first <tr>) for known header labels and
        falls back to position-based heuristics when headers are absent or
        use unfamiliar text.
        """
        col_map = {}
        headers = []

        thead = table.find("thead")
        if thead:
            for th in thead.find_all("th"):
                headers.append(th.get_text(strip=True).lower())
        else:
            first_row = table.find("tr")
            if first_row:
                for th in first_row.find_all(["th", "td"]):
                    headers.append(th.get_text(strip=True).lower())

        for i, h in enumerate(headers):
            h = h.strip()
            if h in ("bl", "backlinks", "bl.", "lbl"):
                col_map["bl"] = i
            elif h in ("dp", "domainpop", "domain pop", "dp.", "ldp"):
                col_map["dp"] = i
            elif h in ("aby", "aby.", "birth", "archive", "archiveorg", "age"):
                col_map["aby"] = i
            elif h in ("status", "whois", "whois status"):
                col_map["status"] = i

        # Position-based fallback when header mapping fails.
        # member.expireddomains.net layout: 0=domain 1=? 2=? 3=LE 4=BL 5=DP 6=WBY 7=ABY
        if "bl" not in col_map and len(headers) > 4:
            col_map["bl"] = 4
        if "dp" not in col_map and len(headers) > 5:
            col_map["dp"] = 5
        if "aby" not in col_map and len(headers) > 7:
            col_map["aby"] = 7

        return col_map

    @staticmethod
    def _extract_domain_from_cell(cell):
        """Pull the domain name out of the first table cell.

        The member portal wraps the domain in <a class="namelinks"> whose
        title attribute always contains the full untruncated domain name.
        We use that first to avoid picking up registrar link text
        (e.g. 'Namecheap.com') when the display text is truncated.
        """
        domain_re = re.compile(
            r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?\.([a-z]{2,10})$'
        )

        # Primary: namelinks anchor — use title attribute (never truncated)
        namelinks = cell.find("a", class_="namelinks")
        if namelinks:
            title = namelinks.get("title", "").lower().strip()
            if title and domain_re.match(title):
                return title
            # Fall back to text if title is absent/odd
            text = namelinks.get_text(strip=True).lower()
            if domain_re.match(text):
                return text

        # Secondary: any <a> whose text looks like a domain, skipping
        # registrar/favicon links which also have domain-looking text.
        for a in cell.find_all("a"):
            classes = a.get("class") or []
            if any("fav" in c for c in classes):
                continue
            text = a.get_text(strip=True).lower()
            if domain_re.match(text):
                return text

        # Last resort: scan cell text for a domain-shaped token
        cell_text = cell.get_text(" ", strip=True).lower()
        m = re.search(
            r'([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?'
            r'\.(?:com|net|org|io|co|us|info|biz|xyz|me|app|ai))',
            cell_text,
        )
        return m.group(1) if m else None

    # ------------------------------------------------------------------
    # Public search methods
    # ------------------------------------------------------------------

    def search_expireddomains(self, keyword=None, tld="com", min_backlinks=0,
                              min_age_years=1, max_results=50, category=None,
                              human_readable_only=True):
        """Search expireddomains.net for available aged domains.

        Uses a POST request to the member portal which requires a logged-in
        session.  Keyword and TLD filters use the correct field names
        (fdomain / ftlds[]) and only available domains are returned.
        """
        if not _REQUESTS_AVAILABLE or not _BS4_AVAILABLE:
            return [{"error": True, "message": "requests and/or bs4 not installed"}]

        if not self._logged_in:
            return [{
                "error": True,
                "message": (
                    "expireddomains.net requires a login to use keyword search "
                    "and backlink filters. Add your expireddomains.net credentials "
                    "in Settings, then retry."
                ),
            }]

        # Build the keyword: explicit keyword takes priority over category
        effective_keyword = keyword
        if not effective_keyword and category:
            effective_keyword = CATEGORY_KEYWORDS.get(category, [""])[0]

        # Resolve TLD(s) to numeric IDs used by ExpiredDomains filters.
        selected_tld = (tld or "").lower().lstrip(".")
        if selected_tld:
            tld_ids = [_TLD_IDS.get(selected_tld, "2")]
        else:
            # "Any" defaults to common TLDs for predictable result quality.
            tld_ids = [_TLD_IDS["com"], _TLD_IDS["net"], _TLD_IDS["org"]]

        results = []
        seen_domains = set()

        # Build base POST payload — field names come from member portal forms.
        base_payload = [
            ("fwhois",  "22"),   # only available domains
            ("fadult",  "1"),    # hide adult names
            ("o",       "bl"),   # sort by backlinks
            ("r",       "d"),    # descending
            ("flimit",  "25"),
        ]
        for tid in tld_ids:
            base_payload.append(("ftlds[]", tid))
        if effective_keyword:
            base_payload.append(("fdomain", effective_keyword))
            base_payload.append(("fdomainstart", ""))
            base_payload.append(("fdomainend", ""))
        if min_backlinks > 0:
            base_payload.append(("fbl", str(min_backlinks)))
        # NOTE: do NOT send fabirth_yearmax here — it limits to only very
        # recent domains and cuts out older high-BL results. Age filtering
        # is done in post-processing using the ABY column value.

        # Fetch up to 3 pages to build our result pool
        for page in range(1, 4):
            if len(results) >= max_results:
                break

            # Pagination offset (25 rows per page)
            base_search_url = self._search_url or self._SEARCH_URL
            page_start = str((page - 1) * 25)
            query_params = [
                ("fwhois", "22"),
                ("fadult", "1"),
                ("o", "bl"),
                ("r", "d"),
                ("flimit", "25"),
                ("start", page_start),
            ]
            for tid in tld_ids:
                query_params.append(("ftlds[]", tid))
            if effective_keyword:
                query_params.extend([
                    ("fdomain", effective_keyword),
                    ("fdomainstart", ""),
                    ("fdomainend", ""),
                ])
            if min_backlinks > 0:
                query_params.append(("fbl", str(min_backlinks)))

            try:
                # Try GET first (domainhunter-compatible), then POST fallback.
                resp = self.session.get(
                    base_search_url,
                    params=query_params,
                    headers={"Referer": base_search_url},
                    timeout=25,
                    allow_redirects=True,
                )
                if resp.status_code != 200:
                    resp = self.session.post(
                        base_search_url,
                        data=base_payload + [("start", page_start)],
                        headers={
                            "Referer": base_search_url,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        timeout=25,
                        allow_redirects=True,
                    )
                    if resp.status_code != 200:
                        break

                soup = BeautifulSoup(resp.text, "html.parser")
                page_text = soup.get_text(separator=" ", strip=True).lower()

                # Detect auth failure / captcha walls
                if "captcha" in page_text:
                    return [{"error": True, "message": "expireddomains.net is showing a CAPTCHA. Try again later."}]
                if "please login" in page_text or "you must be logged in" in page_text or "/login/" in (resp.url or "").lower():
                    # Try alternate search hosts once if current host bounced to login.
                    for alternate in self._search_candidates():
                        if alternate == base_search_url:
                            continue
                        alt_resp = self.session.get(
                            alternate,
                            params=query_params,
                            headers={"Referer": alternate},
                            timeout=25,
                            allow_redirects=True,
                        )
                        if alt_resp.status_code != 200:
                            continue
                        alt_soup = BeautifulSoup(alt_resp.text, "html.parser")
                        alt_text = alt_soup.get_text(separator=" ", strip=True).lower()
                        if (
                            "captcha" in alt_text
                            or "please login" in alt_text
                            or "you must be logged in" in alt_text
                            or "/login/" in (alt_resp.url or "").lower()
                        ):
                            continue
                        self._search_url = alternate
                        resp = alt_resp
                        soup = alt_soup
                        page_text = alt_text
                        break

                    if "please login" in page_text or "you must be logged in" in page_text or "/login/" in (resp.url or "").lower():
                        return [{"error": True,
                                 "message": "Login failed or session expired. Check your credentials in Settings."}]

                table = soup.find("table", class_="base1")
                if not table:
                    break

                col_map = self._parse_column_map(table)

                tbody = table.find("tbody")
                rows = tbody.find_all("tr") if tbody else table.find_all("tr")[1:]

                page_had_domains = False
                for row in rows:
                    cols = row.find_all("td")
                    if len(cols) < 3:
                        continue

                    domain_name = self._extract_domain_from_cell(cols[0])
                    if not domain_name or domain_name in seen_domains:
                        continue

                    # Keep only domains explicitly marked as available.
                    # If availability cannot be determined, skip the row.
                    status = ""
                    status_idx = col_map.get("status")
                    if status_idx is not None and status_idx < len(cols):
                        status = cols[status_idx].get_text(" ", strip=True).lower()
                    else:
                        row_text = " ".join(c.get_text(" ", strip=True).lower() for c in cols)
                        m = re.search(
                            r"\b(available|auction|pending ?delete|registered|taken|sold|backorder|closeout|reserve)\b",
                            row_text,
                        )
                        if m:
                            status = m.group(1)

                    if not status.startswith("available"):
                        continue

                    seen_domains.add(domain_name)
                    page_had_domains = True

                    col_texts = [c.get_text(strip=True) for c in cols]

                    # BL: prefer the anchor's title attribute which has the
                    # exact integer (e.g. title="10,561,035") over cell text
                    # which includes link labels ("10.6 MMajestic.com…")
                    bl = 0
                    bl_idx = col_map.get("bl")
                    if bl_idx is not None and bl_idx < len(cols):
                        bl_a = cols[bl_idx].find("a")
                        if bl_a and bl_a.get("title"):
                            bl = self._safe_int(bl_a["title"])
                        else:
                            bl = self._safe_int(col_texts[bl_idx])

                    dp_idx = col_map.get("dp")
                    dp = self._safe_int(col_texts[dp_idx]) if dp_idx is not None and dp_idx < len(col_texts) else 0

                    aby_idx = col_map.get("aby")
                    aby = self._parse_archive_age(col_texts[aby_idx]) if aby_idx is not None and aby_idx < len(col_texts) else 0

                    info = {
                        "domain": domain_name,
                        "tld": domain_name.rsplit(".", 1)[-1],
                        "backlinks": bl,
                        "domain_pop": dp,
                        "archive_age": aby,
                    }

                    if info["backlinks"] < min_backlinks:
                        continue
                    if min_age_years > 0 and info["archive_age"] < min_age_years:
                        continue
                    if human_readable_only and not is_human_readable(domain_name.split(".")[0]):
                        continue

                    results.append(info)
                    if len(results) >= max_results:
                        break

                if not page_had_domains:
                    break
                time.sleep(1)

            except Exception:
                break

        if not results:
            return [{
                "error": True,
                "message": (
                    "No results found. Try: reducing Min Backlinks, "
                    "setting Min Age to 0, broadening the keyword, "
                    "or unchecking 'Human-readable only'."
                ),
            }]

        return results

    def search_expireddomains_deleted(self, keyword=None, tld="com",
                                      min_backlinks=0, max_results=50):
        """Alias — delegates to :meth:`search_expireddomains`."""
        return self.search_expireddomains(
            keyword=keyword,
            tld=tld,
            min_backlinks=min_backlinks,
            min_age_years=0,
            max_results=max_results,
        )

    # ------------------------------------------------------------------
    # WHOIS helpers
    # ------------------------------------------------------------------

    def check_domain_availability(self, domain):
        """Use python-whois to check whether *domain* is currently registered.

        Returns a dict::

            {"available": bool,
             "registrar": str | None,
             "expiry_date": str | None,
             "creation_date": str | None}
        """
        result = {
            "available": True,
            "registrar": None,
            "expiry_date": None,
            "creation_date": None,
        }

        if not _WHOIS_AVAILABLE:
            result["error"] = "python-whois is not installed"
            return result

        try:
            w = whois.whois(domain)
        except Exception:
            return result

        if w.domain_name is None and w.registrar is None:
            return result

        result["available"] = False
        result["registrar"] = w.registrar

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            result["creation_date"] = creation.isoformat()
        elif creation is not None:
            result["creation_date"] = str(creation)

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(expiry, datetime):
            result["expiry_date"] = expiry.isoformat()
        elif expiry is not None:
            result["expiry_date"] = str(expiry)

        return result

    def get_whois_age(self, domain):
        """Return WHOIS information for *domain* including age calculation.

        Returns a dict::

            {"domain": str,
             "creation_date": str | None,
             "expiration_date": str | None,
             "updated_date": str | None,
             "registrar": str | None,
             "age_days": int | None,
             "age_years": float | None,
             "name_servers": list[str],
             "status": list[str] | str | None,
             "error": str | None}
        """
        info = {
            "domain": domain,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "registrar": None,
            "age_days": None,
            "age_years": None,
            "name_servers": [],
            "status": None,
            "error": None,
        }

        if not _WHOIS_AVAILABLE:
            info["error"] = "python-whois is not installed"
            return info

        try:
            w = whois.whois(domain)
        except Exception as exc:
            info["error"] = str(exc)
            return info

        info["registrar"] = w.registrar

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d", "%d-%b-%Y"):
                try:
                    creation = datetime.strptime(creation, fmt)
                    break
                except ValueError:
                    continue
        if isinstance(creation, datetime):
            info["creation_date"] = creation.isoformat()
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            delta = now - creation
            info["age_days"] = delta.days
            info["age_years"] = round(delta.days / 365.25, 2)

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(expiry, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d", "%d-%b-%Y"):
                try:
                    expiry = datetime.strptime(expiry, fmt)
                    break
                except ValueError:
                    continue
        if isinstance(expiry, datetime):
            info["expiration_date"] = expiry.isoformat()

        updated = w.updated_date
        if isinstance(updated, list):
            updated = updated[0]
        if isinstance(updated, datetime):
            info["updated_date"] = updated.isoformat()
        elif updated is not None:
            info["updated_date"] = str(updated)

        ns = w.name_servers
        if ns:
            if isinstance(ns, list):
                info["name_servers"] = [str(n).lower() for n in ns]
            else:
                info["name_servers"] = [str(ns).lower()]

        info["status"] = w.status

        return info

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_domain(self, domain_info):
        """Score a domain on a 0-100 scale.

        Point breakdown:
        - Backlinks:  0-25  (more = better)
        - Domain age: 0-25  (older = better)
        - Domain pop: 0-25  (more diverse referring domains = better)
        - TLD:        0-15  (.com best)
        - Name:       0-10  (shorter, no hyphens = better)
        """
        score = 0

        bl = self._safe_int(domain_info.get("backlinks"))
        if bl >= 1000:
            score += 25
        elif bl >= 500:
            score += 20
        elif bl >= 100:
            score += 15
        elif bl >= 50:
            score += 12
        elif bl >= 10:
            score += 8
        elif bl >= 1:
            score += 4

        age = self._safe_int(domain_info.get("archive_age"))
        if age >= 20:
            score += 25
        elif age >= 15:
            score += 22
        elif age >= 10:
            score += 18
        elif age >= 5:
            score += 14
        elif age >= 3:
            score += 10
        elif age >= 1:
            score += 5

        dp = self._safe_int(domain_info.get("domain_pop"))
        if dp >= 500:
            score += 25
        elif dp >= 200:
            score += 20
        elif dp >= 100:
            score += 15
        elif dp >= 50:
            score += 12
        elif dp >= 10:
            score += 8
        elif dp >= 1:
            score += 4

        tld = str(domain_info.get("tld", "")).lower().lstrip(".")
        score += _TLD_SCORES.get(tld, 5)

        domain_name = str(domain_info.get("domain", ""))
        label = domain_name.split(".")[0] if "." in domain_name else domain_name
        name_score = 10
        if "-" in label:
            name_score -= 3
        if len(label) > 20:
            name_score -= 3
        elif len(label) > 14:
            name_score -= 2
        elif len(label) > 10:
            name_score -= 1
        if any(ch.isdigit() for ch in label):
            name_score -= 1
        score += max(name_score, 0)

        return min(score, 100)

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def filter_results(self, results, min_score=0, exclude_hyphens=True,
                       max_length=20, preferred_tlds=None):
        """Filter and sort domain results by score."""
        filtered = []
        for item in results:
            if item.get("error"):
                continue

            domain = str(item.get("domain", ""))
            label = domain.split(".")[0] if "." in domain else domain

            if exclude_hyphens and "-" in label:
                continue
            if len(label) > max_length:
                continue
            if preferred_tlds:
                tld = item.get("tld", "").lower().lstrip(".")
                if tld not in [t.lower().lstrip(".") for t in preferred_tlds]:
                    continue

            item["score"] = self.score_domain(item)
            if item["score"] < min_score:
                continue

            filtered.append(item)

        filtered.sort(key=lambda d: d.get("score", 0), reverse=True)
        return filtered

    # ------------------------------------------------------------------
    # Convenience wrapper
    # ------------------------------------------------------------------

    def search_and_score(self, keyword=None, tld="com", min_backlinks=5,
                         min_age_years=1, max_results=30, category=None,
                         human_readable_only=True):
        """Search, score, filter, and return sorted expired domain results."""
        raw = self.search_expireddomains(
            keyword=keyword,
            tld=tld,
            min_backlinks=min_backlinks,
            min_age_years=min_age_years,
            max_results=max_results * 3,
            category=category,
            human_readable_only=human_readable_only,
        )

        if raw and raw[0].get("error"):
            return raw

        scored = self.filter_results(raw, min_score=0)
        return scored[:max_results]


# ===================================================================
# Custom (No ExpiredDomains Account) finder
# ===================================================================

_CUSTOM_DEFAULT_SEEDS = (
    "health", "finance", "care", "clinic", "capital", "advisory", "systems",
    "research", "digital", "academy", "wellness", "solutions", "partners",
    "group", "analytics", "media", "network", "ventures", "trust", "labs",
)

_CUSTOM_DEFAULT_TLDS = ("com", "net", "org")
_MULTIPART_TLDS = {"co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.in", "co.za"}
_CANDIDATE_MODIFIERS = (
    "pro", "prime", "smart", "secure", "rapid", "core", "global", "first", "true", "next",
    "nova", "apex", "bridge", "summit", "north", "zen", "alpha", "assist", "desk", "help",
    "online", "digital", "cloud", "hub", "center", "point", "flow", "link", "works", "labs",
    "group", "network", "partners", "solutions", "systems", "care", "trust", "intel",
)
_CANDIDATE_PREFIXES = (
    "get", "go", "my", "join", "the", "ask", "hello", "try", "best", "prime", "core", "pro",
    "team", "true", "rapid", "smart", "first", "next", "open",
)
_CANDIDATE_SUFFIXES = (
    "hq", "hub", "desk", "group", "labs", "works", "systems", "solutions", "partners",
    "network", "center", "service", "services", "support", "care", "health", "capital",
    "media", "digital", "cloud", "academy", "insights", "ops", "global",
)
_KEYWORD_EXPANSIONS = {
    "support": ("assist", "help", "desk", "service", "team", "care"),
    "health": ("clinic", "medical", "wellness", "care", "telehealth"),
    "finance": ("capital", "wealth", "asset", "fund", "fiscal"),
    "security": ("secure", "shield", "defense", "guard", "trust"),
    "education": ("academy", "learning", "training", "institute"),
    "marketing": ("brand", "creative", "agency", "growth", "media"),
    "consulting": ("advisory", "partners", "strategy", "solutions"),
    "travel": ("tour", "resort", "trip", "journey", "vacation"),
}


class CustomDomainFinder:
    """Find available domains with historical trust signals without ExpiredDomains."""

    def __init__(self):
        self.last_error = ""
        self.last_info = {}
        self.engine_name = "Custom Domain Intelligence"
        self._wayback_cache = {}
        self.session = None
        if _REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update(_DEFAULT_HEADERS)
        self._availability_cache = {}

    @staticmethod
    def _keyword_labels(keyword):
        labels = []
        if not keyword:
            return labels

        words = re.findall(r"[a-z0-9]+", str(keyword).lower())
        if words:
            joined = "".join(words)
            if 4 <= len(joined) <= 24:
                labels.append(joined)
            if len(words) >= 2:
                dashed = "-".join(words)
                if 4 <= len(dashed) <= 24:
                    labels.append(dashed)

        literal = re.sub(r"[^a-z0-9\-]", "", str(keyword).lower()).strip("-")
        if 4 <= len(literal) <= 24 and re.match(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$", literal):
            labels.append(literal)

        dedup = []
        seen = set()
        for label in labels:
            if label not in seen:
                dedup.append(label)
                seen.add(label)
        return dedup

    @staticmethod
    def _normalize_host(host):
        value = (host or "").strip().lower()
        if not value:
            return ""
        if "://" in value:
            value = value.split("://", 1)[1]
        value = value.split("/", 1)[0].strip(".")
        if value.startswith("*."):
            value = value[2:]
        return value

    @staticmethod
    def _is_domain(value):
        return bool(re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z]{2,24})+$", value or ""))

    @staticmethod
    def _extract_registrable(host):
        parts = (host or "").split(".")
        if len(parts) < 2:
            return ""
        tail2 = ".".join(parts[-2:])
        tail3 = ".".join(parts[-3:]) if len(parts) >= 3 else ""
        if tail2 in _MULTIPART_TLDS and len(parts) >= 3:
            return tail3
        if tail3 in _MULTIPART_TLDS and len(parts) >= 4:
            return ".".join(parts[-4:])
        return tail2

    def _seed_terms(self, keyword=None, category=None):
        seeds = []
        if keyword:
            seeds.extend(re.findall(r"[a-z0-9]{2,}", keyword.lower()))
        if category and category in CATEGORY_KEYWORDS:
            seeds.extend(CATEGORY_KEYWORDS[category][:10])
        if not seeds:
            seeds.extend(_CUSTOM_DEFAULT_SEEDS)
        expanded = []
        for seed in seeds:
            expanded.extend(_KEYWORD_EXPANSIONS.get(seed, ()))
        seeds.extend(expanded)

        dedup = []
        seen = set()
        for s in seeds:
            s = re.sub(r"[^a-z0-9]", "", (s or "").lower())
            if len(s) < 3 or len(s) > 18:
                continue
            if s not in seen:
                dedup.append(s)
                seen.add(s)
        return dedup[:18]

    def _crt_seed_candidates(self, seeds, tld="", max_domains=600):
        """Use Certificate Transparency data to discover historical domains."""
        metrics = {}
        if not self.session:
            return metrics

        selected_tld = (tld or "").lower().lstrip(".")
        for seed in seeds[:6]:
            try:
                resp = self.session.get(
                    "https://crt.sh/",
                    params={"q": f"%{seed}%", "output": "json"},
                    timeout=20,
                )
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            try:
                rows = resp.json()
            except Exception:
                continue

            if not isinstance(rows, list):
                continue

            for row in rows[:3000]:
                names = str(row.get("name_value", "")).splitlines()
                for raw in names:
                    host = self._normalize_host(raw)
                    if not host or not self._is_domain(host):
                        continue
                    root = self._extract_registrable(host)
                    if not root or not self._is_domain(root):
                        continue
                    if selected_tld and not root.endswith("." + selected_tld):
                        continue
                    data = metrics.setdefault(root, {"hits": 0, "subdomains": set()})
                    data["hits"] += 1
                    if host != root and host.endswith("." + root):
                        data["subdomains"].add(host)
                    if len(metrics) >= max_domains:
                        return metrics
        return metrics

    def _algorithmic_candidates(self, seeds, tld="", max_domains=500):
        """Generate a broad, readable candidate set from terms."""
        tlds = [tld.lower().lstrip(".")] if tld else list(_CUSTOM_DEFAULT_TLDS)
        out = []
        seen = set()

        def add_label(label):
            label = (label or "").strip().lower()
            if not label:
                return False
            if len(label) < 4 or len(label) > 24:
                return False
            if not re.match(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$", label):
                return False
            for ext in tlds:
                domain = f"{label}.{ext}"
                if domain in seen:
                    continue
                out.append(domain)
                seen.add(domain)
                if len(out) >= max_domains:
                    return True
            return False

        terms = list(seeds[:18])
        modifiers = [m for m in _CANDIDATE_MODIFIERS if m not in terms][:24]

        for seed in terms:
            if add_label(seed):
                return out
            for suf in _CANDIDATE_SUFFIXES:
                if add_label(f"{seed}{suf}"):
                    return out
                if add_label(f"{seed}-{suf}"):
                    return out
            for pre in _CANDIDATE_PREFIXES:
                if add_label(f"{pre}{seed}"):
                    return out
                if add_label(f"{pre}-{seed}"):
                    return out
            for mod in modifiers[:14]:
                if add_label(f"{seed}{mod}"):
                    return out
                if add_label(f"{mod}{seed}"):
                    return out
                if add_label(f"{seed}-{mod}"):
                    return out

        combo_words = terms[:12] + modifiers[:20]
        for a in combo_words:
            for b in combo_words:
                if a == b:
                    continue
                if add_label(f"{a}{b}"):
                    return out
                if add_label(f"{a}-{b}"):
                    return out
            for suf in _CANDIDATE_SUFFIXES[:10]:
                if add_label(f"{a}{suf}"):
                    return out

        return out

    @staticmethod
    def _parse_dt(value):
        if not value:
            return None
        text = str(value).strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except Exception:
            pass
        for fmt in ("%Y-%m-%d", "%Y%m%d%H%M%S"):
            try:
                return datetime.strptime(text[:len(fmt)], fmt)
            except Exception:
                continue
        return None

    def _rdap_urls_for_domain(self, domain):
        tld = domain.rsplit(".", 1)[-1].lower()
        urls = []
        if tld == "com":
            urls.append(("rdap_verisign_com", f"https://rdap.verisign.com/com/v1/domain/{domain}"))
        elif tld == "net":
            urls.append(("rdap_verisign_net", f"https://rdap.verisign.com/net/v1/domain/{domain}"))
        urls.append(("rdap_org", f"https://rdap.org/domain/{domain}"))
        if tld:
            urls.append((f"rdap_nic_{tld}", f"https://rdap.nic.{tld}/domain/{domain}"))

        dedup = []
        seen = set()
        for source, url in urls:
            if url in seen:
                continue
            dedup.append((source, url))
            seen.add(url)
        return dedup

    def _age_years_from_rdap_payload(self, payload):
        if not isinstance(payload, dict):
            return 0
        created = payload.get("creationDate")
        if not created:
            for ev in payload.get("events", []) or []:
                action = str(ev.get("eventAction", "")).lower()
                if action in ("registration", "created"):
                    created = ev.get("eventDate")
                    break
        dt = self._parse_dt(created)
        if not dt:
            return 0
        return max(0, int((datetime.now() - dt.replace(tzinfo=None)).days / 365.25))

    def _rdap_availability(self, domain):
        if domain in self._availability_cache:
            return self._availability_cache[domain]

        result = {"available": None, "age_years": 0, "source": "unverified"}
        if not self.session:
            self._availability_cache[domain] = result
            return result

        rdap_unregistered = False
        rdap_registered = False
        rdap_source = None

        for source, url in self._rdap_urls_for_domain(domain):
            try:
                resp = self.session.get(url, timeout=7, allow_redirects=True)
            except Exception:
                continue

            if resp.status_code == 200:
                rdap_registered = True
                rdap_source = source
                try:
                    payload = resp.json()
                except Exception:
                    payload = {}
                result["age_years"] = max(result["age_years"], self._age_years_from_rdap_payload(payload))
                break
            if resp.status_code in (404, 410):
                trusted_not_found = source.startswith("rdap_org") or source.startswith("rdap_verisign")
                if not trusted_not_found:
                    body = (resp.text or "").lower()
                    content_type = str(resp.headers.get("Content-Type", "")).lower()
                    if "html" not in content_type and domain in body and any(
                        marker in body for marker in ("not found", "no object", "does not exist")
                    ):
                        trusted_not_found = True
                if trusted_not_found:
                    rdap_unregistered = True
                    rdap_source = source

        whois_unregistered = False
        whois_registered = False
        whois_source = None
        if _WHOIS_AVAILABLE and not rdap_registered and not rdap_unregistered:
            try:
                w = whois.whois(domain)
                has_record = bool(
                    getattr(w, "domain_name", None)
                    or getattr(w, "registrar", None)
                    or getattr(w, "status", None)
                    or getattr(w, "name_servers", None)
                    or getattr(w, "creation_date", None)
                )
                if has_record:
                    whois_registered = True
                    whois_source = "whois_record"
            except Exception as exc:
                msg = str(exc).lower()
                label = domain.split(".", 1)[0]
                unregistered_markers = (
                    "no match for domain",
                    "not found in database",
                    "domain not found",
                    "status: free",
                    "object does not exist",
                    "no entries found",
                )
                if any(token in msg for token in unregistered_markers) and (domain in msg or label in msg):
                    whois_unregistered = True
                    whois_source = "whois_unregistered"

        dns_resolves = False
        try:
            socket.getaddrinfo(domain, None)
            dns_resolves = True
        except Exception:
            dns_resolves = False

        if rdap_registered or whois_registered or dns_resolves:
            result["available"] = False
            if rdap_registered:
                result["source"] = rdap_source or "rdap_registered"
            elif whois_registered:
                result["source"] = whois_source or "whois_record"
            else:
                result["source"] = "dns_resolves"
        elif rdap_unregistered:
            result["available"] = True
            result["source"] = rdap_source or "rdap_unregistered"
        elif whois_unregistered and not dns_resolves:
            result["available"] = True
            result["source"] = whois_source or "whois_unregistered"
        else:
            result["available"] = None
            result["source"] = "unverified"

        self._availability_cache[domain] = result
        return result

    def _wayback_metrics(self, domain):
        if domain in self._wayback_cache:
            return self._wayback_cache[domain]
        info = get_wayback_info(domain)
        snapshots = int(info.get("total_snapshots") or 0)
        first = self._parse_dt(info.get("first_snapshot_date"))
        age = 0
        if first:
            age = max(0, int((datetime.now() - first.replace(tzinfo=None)).days / 365.25))
        out = {"total_snapshots": snapshots, "archive_age": age}
        self._wayback_cache[domain] = out
        return out

    def _seed_bonus(self, label, seeds):
        bonus = 0
        for seed in seeds:
            if label == seed:
                bonus += 20
            elif label.startswith(seed):
                bonus += 16
            elif label.endswith(seed):
                bonus += 12
            elif seed in label:
                bonus += 8
        return min(40, bonus)

    def _make_candidate_row(self, domain, seeds, ct_metrics):
        label = domain.split(".")[0]
        ct = ct_metrics.get(domain, {})
        ct_hits = int(ct.get("hits") or 0)
        sub_count = len(ct.get("subdomains") or ())
        seed_bonus = self._seed_bonus(label, seeds)

        backlinks = (ct_hits * 3) + (sub_count * 18) + seed_bonus
        domain_pop = (sub_count * 9) + max(0, ct_hits // 2)
        lexical_bonus = 0
        if "-" not in label:
            lexical_bonus += 6
        if 6 <= len(label) <= 14:
            lexical_bonus += 8
        if not any(ch.isdigit() for ch in label):
            lexical_bonus += 4
        priority = seed_bonus + lexical_bonus + min(120, ct_hits * 2) + min(80, sub_count * 6)

        return {
            "domain": domain,
            "tld": domain.rsplit(".", 1)[-1],
            "backlinks": int(max(0, backlinks)),
            "domain_pop": int(max(0, domain_pop)),
            "archive_age": 0,
            "available": None,
            "availability_source": "pending",
            "priority": int(priority),
            "signals": {
                "seed_bonus": seed_bonus,
                "ct_hits": ct_hits,
                "ct_subdomains": sub_count,
            },
        }

    def _enrich_historical_signals(self, row):
        wayback = self._wayback_metrics(row["domain"])
        snapshots = int(wayback.get("total_snapshots") or 0)
        wayback_age = int(wayback.get("archive_age") or 0)

        row["backlinks"] = int(row.get("backlinks", 0) + min(2500, snapshots * 2))
        row["domain_pop"] = int(row.get("domain_pop", 0) + min(1200, snapshots // 3))
        row["archive_age"] = max(int(row.get("archive_age", 0) or 0), wayback_age)
        row["signals"]["wayback_snapshots"] = snapshots
        return row

    def _compute_final_score(self, row, scorer):
        base = int(scorer.score_domain(row))
        domain = str(row.get("domain", ""))
        label = domain.split(".")[0] if "." in domain else domain
        signals = row.get("signals") or {}
        seed_bonus = int(signals.get("seed_bonus") or 0)

        boost = 0
        if seed_bonus >= 20:
            boost += 12
        elif seed_bonus >= 16:
            boost += 9
        elif seed_bonus >= 8:
            boost += 5
        if signals.get("forced_keyword_match"):
            boost += 8

        penalty = 0
        hyphen_count = label.count("-")
        if hyphen_count > 0:
            penalty += 8 + max(0, hyphen_count - 1) * 3
        label_len = len(label)
        if label_len > 12:
            penalty += min(12, label_len - 12)
        if label_len > 18:
            penalty += min(8, label_len - 18)
        if any(ch.isdigit() for ch in label):
            penalty += 3
        if row.get("archive_age", 0) <= 1 and row.get("backlinks", 0) < 60:
            penalty += 4

        return max(0, min(100, base + boost - penalty))

    def search_and_score(
        self,
        keyword=None,
        tld="com",
        min_backlinks=5,
        min_age_years=1,
        max_results=30,
        category=None,
        human_readable_only=True,
        available_only=True,
    ):
        seeds = self._seed_terms(keyword=keyword, category=category)
        selected_tld = (tld or "").lower().lstrip(".")
        selected_tlds = [selected_tld] if selected_tld else list(_CUSTOM_DEFAULT_TLDS)
        forced_keyword_domains = []
        for label in self._keyword_labels(keyword):
            for ext in selected_tlds:
                forced_keyword_domains.append(f"{label}.{ext}")
        forced_keyword_set = set(forced_keyword_domains)

        ct_metrics = self._crt_seed_candidates(
            seeds,
            tld=selected_tld,
            max_domains=max(1800, max_results * 70),
        )
        generated = self._algorithmic_candidates(
            seeds,
            tld=selected_tld,
            max_domains=max(2500, max_results * 120),
        )

        ordered_domains = []
        seen_domains = set()

        for domain in forced_keyword_domains:
            if domain not in seen_domains:
                ordered_domains.append(domain)
                seen_domains.add(domain)

        crt_sorted = sorted(
            ct_metrics.items(),
            key=lambda kv: (int((kv[1] or {}).get("hits") or 0), len((kv[1] or {}).get("subdomains") or ())),
            reverse=True,
        )
        for domain, _ in crt_sorted:
            if domain not in seen_domains:
                ordered_domains.append(domain)
                seen_domains.add(domain)
        for domain in generated:
            if domain not in seen_domains:
                ordered_domains.append(domain)
                seen_domains.add(domain)

        if not ordered_domains:
            self.last_error = "No candidates could be generated for this query."
            return [{"error": True, "message": self.last_error}]

        scorer = DomainFinder()
        candidate_rows = []
        for domain in ordered_domains:
            label = domain.split(".")[0]
            if human_readable_only and domain not in forced_keyword_set and not is_human_readable(label):
                continue
            row = self._make_candidate_row(domain, seeds, ct_metrics)
            if domain in forced_keyword_set:
                row["signals"]["forced_keyword_match"] = True
                row["priority"] += 90
                row["backlinks"] = int(row.get("backlinks", 0) + 40)
            candidate_rows.append(row)

        if not candidate_rows:
            self.last_error = "No candidates matched readability constraints. Try disabling human-readable-only."
            return [{"error": True, "message": self.last_error}]

        candidate_rows.sort(
            key=lambda item: (item.get("priority", 0), item.get("backlinks", 0), item.get("domain_pop", 0)),
            reverse=True,
        )
        eval_limit = min(len(candidate_rows), max(800, max_results * 90))
        eval_rows = candidate_rows[:eval_limit]

        def check_avail(row):
            info = self._rdap_availability(row["domain"])
            row["available"] = info.get("available")
            row["availability_source"] = info.get("source")
            row["archive_age"] = max(row.get("archive_age", 0), int(info.get("age_years", 0) or 0))
            row["score"] = self._compute_final_score(row, scorer)
            return row

        checked = []
        workers = min(16, max(4, max_results))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(check_avail, row) for row in eval_rows]
            for fut in as_completed(futures):
                try:
                    checked.append(fut.result())
                except Exception:
                    continue

        candidate_pool = []
        for row in checked:
            if row.get("available") is False:
                continue
            if available_only and row.get("available") is not True:
                continue
            if not available_only and row.get("available") is None:
                row["notes"] = "Availability is unverified; run all checks before onboarding."
            candidate_pool.append(row)

        if not candidate_pool and available_only:
            self.last_error = (
                "No verified available domains matched this query. Try another keyword/TLD or uncheck available-only."
            )
            return [{"error": True, "message": self.last_error}]

        candidate_pool.sort(
            key=lambda item: (item.get("backlinks", 0), item.get("domain_pop", 0), item.get("priority", 0)),
            reverse=True,
        )

        enrich_limit = min(len(candidate_pool), max(120, max_results * 8))
        to_enrich = candidate_pool[:enrich_limit]
        enriched = []
        if to_enrich:
            enrich_workers = min(10, max(4, max_results))
            with ThreadPoolExecutor(max_workers=enrich_workers) as pool:
                futures = [pool.submit(self._enrich_historical_signals, row) for row in to_enrich]
                for fut in as_completed(futures):
                    try:
                        enriched.append(fut.result())
                    except Exception:
                        continue
        enriched_map = {r["domain"]: r for r in enriched if r.get("domain")}
        for idx, row in enumerate(candidate_pool):
            if row.get("domain") in enriched_map:
                candidate_pool[idx] = enriched_map[row["domain"]]

        results = []
        for row in candidate_pool:
            if row["backlinks"] < int(min_backlinks or 0):
                continue
            if row["archive_age"] < int(min_age_years or 0):
                continue
            row["score"] = self._compute_final_score(row, scorer)
            results.append(row)
        results.sort(key=lambda item: (item.get("score", 0), item.get("backlinks", 0)), reverse=True)
        results = results[:max_results]

        if not results:
            self.last_error = (
                "No domains matched your filters. Try lower minimums or broaden keyword/category."
            )
            return [{"error": True, "message": self.last_error}]

        self.last_info = {
            "engine": self.engine_name,
            "seeds": seeds,
            "crt_candidates": len(ct_metrics),
            "generated_candidates": len(generated),
            "candidates_considered": len(ordered_domains),
            "candidates_evaluated": len(checked),
            "mode": "verified_available" if available_only else "mixed_verified_unverified",
            "available_candidates": len(candidate_pool),
            "enriched_candidates": len(enriched_map),
            "results": len(results),
        }
        return results


# ===================================================================
# Standalone utility functions
# ===================================================================

def get_wayback_info(domain):
    """Query the Wayback Machine Availability API for *domain*.

    Returns a dict::

        {"domain": str,
         "has_snapshots": bool,
         "first_snapshot_date": str | None,
         "last_snapshot_date": str | None,
         "total_snapshots": int | None,
         "closest_url": str | None,
         "error": str | None}
    """
    info = {
        "domain": domain,
        "has_snapshots": False,
        "first_snapshot_date": None,
        "last_snapshot_date": None,
        "total_snapshots": None,
        "closest_url": None,
        "error": None,
    }

    if not _REQUESTS_AVAILABLE:
        info["error"] = "requests library not installed"
        return info

    try:
        resp = requests.get(
            "https://archive.org/wayback/available",
            params={"url": domain},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            snapshot = (data.get("archived_snapshots") or {}).get("closest")
            if snapshot:
                info["has_snapshots"] = True
                info["closest_url"] = snapshot.get("url")
                ts = snapshot.get("timestamp", "")
                if ts:
                    try:
                        dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
                        info["last_snapshot_date"] = dt.isoformat()
                    except ValueError:
                        info["last_snapshot_date"] = ts
    except requests.RequestException as exc:
        info["error"] = f"Wayback availability check failed: {exc}"
        return info

    try:
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        resp_first = requests.get(
            cdx_url,
            params={"url": domain, "output": "json", "limit": "1", "fl": "timestamp"},
            timeout=10,
        )
        if resp_first.status_code == 200:
            rows = resp_first.json()
            if len(rows) > 1:
                ts = rows[1][0]
                try:
                    dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
                    info["first_snapshot_date"] = dt.isoformat()
                except ValueError:
                    info["first_snapshot_date"] = ts
                info["has_snapshots"] = True

        resp_count = requests.get(
            cdx_url,
            params={"url": domain, "output": "json", "limit": "0", "showNumPages": "true"},
            timeout=10,
        )
        if resp_count.status_code == 200:
            try:
                info["total_snapshots"] = int(resp_count.text.strip())
            except ValueError:
                pass
    except requests.RequestException:
        pass

    return info


def check_domain_reputation_quick(domain):
    """Run quick, key-free reputation checks on *domain*.

    Returns a dict::

        {"domain": str,
         "resolves": bool,
         "resolved_ips": list[str],
         "safe_browsing_page_accessible": bool | None,
         "error": str | None}
    """
    import socket

    result = {
        "domain": domain,
        "resolves": False,
        "resolved_ips": [],
        "safe_browsing_page_accessible": None,
        "error": None,
    }

    try:
        answers = socket.getaddrinfo(domain, None)
        ips = list({addr[4][0] for addr in answers})
        if ips:
            result["resolves"] = True
            result["resolved_ips"] = ips
    except socket.gaierror:
        pass
    except Exception as exc:
        result["error"] = f"DNS lookup error: {exc}"

    if _REQUESTS_AVAILABLE:
        try:
            sb_url = (
                "https://transparencyreport.google.com/safe-browsing/"
                f"search?url={domain}"
            )
            resp = requests.head(sb_url, timeout=8, allow_redirects=True)
            result["safe_browsing_page_accessible"] = resp.status_code == 200
        except requests.RequestException:
            result["safe_browsing_page_accessible"] = None
    else:
        result["safe_browsing_page_accessible"] = None

    return result


def comprehensive_domain_lookup(domain, config=None):
    """Run a comprehensive lookup on a domain: WHOIS + Wayback + reputation."""
    result = {"domain": domain, "checked_at": datetime.now(timezone.utc).isoformat()}

    finder = DomainFinder()
    result["whois"] = finder.get_whois_age(domain)
    result["wayback"] = get_wayback_info(domain)
    result["quick_rep"] = check_domain_reputation_quick(domain)

    return result
