import os
import re
import json
import time
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, urljoin, urldefrag
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import requests
import pandas as pd
from bs4 import BeautifulSoup


# =========================
# CONFIG
# =========================
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

BLOCK_PATTERNS = [
    r"verify you are human",
    r"checking your browser",
    r"cloudflare",
    r"captcha",
    r"bot detection",
    r"access denied",
    r"unusual traffic",
    r"waf",
    r"request blocked",
    r"security check",
]


# =========================
# Helpers
# =========================
def _clean_text(s: Any) -> str:
    if s is None:
        return ""
    return re.sub(r"\s+", " ", str(s)).strip()

def _safe_int(x, default=0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def _strip_query(url: str) -> str:
    try:
        p = urlparse(url)
        return p._replace(query="", fragment="").geturl()
    except Exception:
        return url

def _same_domain(a: str, b: str) -> bool:
    try:
        return urlparse(a).netloc.lower() == urlparse(b).netloc.lower()
    except Exception:
        return False

def _normalize_url(url: str) -> str:
    # Remove fragments, strip query, keep trailing slash consistent-ish
    url = _clean_text(url)
    url, _ = urldefrag(url)
    url = _strip_query(url)
    return url

def detect_soft_block(status_code: int, text: str, headers: Dict[str, str]) -> Tuple[bool, str]:
    """
    Detect WAF/challenge/soft-block pages.
    """
    if status_code in (202, 403, 429):
        # common with bot protection
        hay = (text or "")[:5000].lower()
        for pat in BLOCK_PATTERNS:
            if re.search(pat, hay, flags=re.IGNORECASE):
                return True, f"Possible bot/WAF challenge detected (status {status_code})."
        # even without text signals, 429/403 are strong signs
        if status_code in (403, 429):
            return True, f"Access likely blocked/rate-limited (status {status_code})."
        if status_code == 202:
            return True, "Soft-block suspected (HTTP 202)."
    # also check headers
    server = (headers.get("server") or "").lower()
    if "cloudflare" in server:
        hay = (text or "")[:5000].lower()
        for pat in BLOCK_PATTERNS:
            if re.search(pat, hay, flags=re.IGNORECASE):
                return True, "Cloudflare/bot challenge detected."
    return False, ""

def make_session(user_agent: str = DEFAULT_UA) -> requests.Session:
    """
    Shared session with retries for transient failures.
    """
    s = requests.Session()
    s.headers.update({
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    retries = Retry(
        total=3,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
        respect_retry_after_header=True,
    )

    adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


# =========================
# Fetching
# =========================
@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: int
    headers: Dict[str, str]
    text: str
    blocked: bool
    block_reason: str

def fetch_url(
    url: str,
    timeout: int = 15,
    user_agent: str = DEFAULT_UA,
    session: Optional[requests.Session] = None
) -> FetchResult:
    url = _normalize_url(url)
    s = session or make_session(user_agent)

    try:
        r = s.get(url, timeout=timeout, allow_redirects=True)

        # Only treat as HTML if it looks like HTML
        ctype = (r.headers.get("Content-Type") or "").lower()
        text = r.text or ""

        is_html = ("text/html" in ctype) or ("application/xhtml+xml" in ctype) or ("<html" in text[:500].lower())

        blocked, reason = detect_soft_block(r.status_code, text if is_html else "", dict(r.headers))

        # If not HTML, don't parse (but still return status + final url)
        return FetchResult(
            url=url,
            final_url=_normalize_url(r.url),
            status_code=r.status_code,
            headers=dict(r.headers),
            text=text if is_html else "",
            blocked=blocked,
            block_reason=reason if blocked else ("" if is_html else f"Non-HTML content-type: {ctype or 'unknown'}"),
        )

    except requests.exceptions.Timeout:
        return FetchResult(url=url, final_url=url, status_code=0, headers={}, text="", blocked=True, block_reason="Timeout")
    except Exception as e:
        return FetchResult(url=url, final_url=url, status_code=0, headers={}, text="", blocked=True, block_reason=f"Error: {e}")



# =========================
# HTML Parsing
# =========================
def parse_page(html: str, base_url: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html or "", "html.parser")

    title = _clean_text(soup.title.string) if soup.title and soup.title.string else ""
    meta_desc = ""
    canonical = ""
    meta_robots = ""
    viewport = ""

    og_title = ""
    og_desc = ""
    og_image = ""

    # meta
    for m in soup.find_all("meta"):
        name = (m.get("name") or "").lower().strip()
        prop = (m.get("property") or "").lower().strip()
        content = _clean_text(m.get("content"))
        if name == "description":
            meta_desc = content
        elif name == "robots":
            meta_robots = content
        elif name == "viewport":
            viewport = content
        if prop == "og:title":
            og_title = content
        elif prop == "og:description":
            og_desc = content
        elif prop == "og:image":
            og_image = content

    # canonical
    link_can = soup.find("link", rel=lambda x: x and "canonical" in x)
    if link_can and link_can.get("href"):
        canonical = _clean_text(link_can.get("href"))

    # headings
    h1s = [_clean_text(h.get_text(" ")) for h in soup.find_all("h1")]
    h2s = [_clean_text(h.get_text(" ")) for h in soup.find_all("h2")]

    # images + alt
    imgs = soup.find_all("img")
    total_images = len(imgs)
    images_with_alt = 0
    for im in imgs:
        alt = im.get("alt")
        if alt is not None and _clean_text(alt) != "":
            images_with_alt += 1

    # links
    internal_links = []
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if not href:
            continue
        href = href.strip()
        if href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:") or href.startswith("javascript:"):
            continue
        abs_url = urljoin(base_url, href)
        abs_url = _normalize_url(abs_url)
        if _same_domain(abs_url, base_url):
            internal_links.append(abs_url)

    # remove duplicates while preserving order
    seen = set()
    uniq_internal = []
    for u in internal_links:
        if u not in seen:
            seen.add(u)
            uniq_internal.append(u)

    return {
        "title": title,
        "meta_description": meta_desc,
        "canonical": canonical,
        "meta_robots": meta_robots,
        "viewport": viewport,
        "og_title": og_title,
        "og_description": og_desc,
        "og_image": og_image,
        "h1s": h1s,
        "h2s": h2s,
        "h1_count": len(h1s),
        "total_images": total_images,
        "images_with_alt": images_with_alt,
        "internal_links": uniq_internal,
    }


# =========================
# Technical SEO
# =========================
def check_robots_and_sitemaps(site_url: str, timeout: int = 15, user_agent: str = DEFAULT_UA) -> Dict[str, Any]:
    sess = make_session(user_agent)
    """
    Fetch robots.txt and infer sitemap URLs.
    """
    site_url = _normalize_url(site_url)
    parsed = urlparse(site_url)
    base = f"{parsed.scheme}://{parsed.netloc}/"

    robots_url = urljoin(base, "robots.txt")
    res = fetch_url(robots_url, timeout=timeout, user_agent=user_agent, session=sess)

    robots_found = (res.status_code == 200 and not res.blocked)
    sitemaps = []

    if robots_found:
        for line in (res.text or "").splitlines():
            if line.lower().startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                if sm:
                    sitemaps.append(_normalize_url(sm))

    # If robots has none, try default sitemap.xml
    if not sitemaps:
        guess = urljoin(base, "sitemap.xml")
        sitemaps.append(_normalize_url(guess))

    sitemap_checks = []
    for sm in sitemaps:
        sm_res = fetch_url(sm, timeout=timeout, user_agent=user_agent, session=sess)
        sitemap_checks.append({
            "sitemap_url": sm,
            "status": sm_res.status_code,
            "blocked": sm_res.blocked,
            "block_reason": sm_res.block_reason
        })

    return {
        "robots_url": robots_url,
        "robots_status": res.status_code,
        "robots_found": robots_found,
        "robots_blocked": res.blocked,
        "robots_block_reason": res.block_reason,
        "sitemaps": sitemap_checks,
        "indexability_headers": {
            "x_robots_tag": (res.headers.get("X-Robots-Tag") or res.headers.get("x-robots-tag") or "")
        }
    }


# =========================
# Crawl
# =========================
def crawl_site(
    start_url: str,
    max_pages: int = 8,
    timeout: int = 15,
    user_agent: str = DEFAULT_UA,
    check_internal_links: bool = True,
    links_per_page: int = 8,
    delay_sec: float = 0.0
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """
    BFS crawl within same domain.
    Returns:
      pages_df: page metrics + extracted meta
      links_df: internal link checks (classified)
      extras: crawl meta (blocked flags etc.)
    """
    start_url = _normalize_url(start_url)
    parsed = urlparse(start_url)
    base = f"{parsed.scheme}://{parsed.netloc}/"
    sess = make_session(user_agent)

    q = deque([start_url])
    visited = set()
    pages = []
    link_rows = []

    # If homepage blocked, we still return a single page row with blocked flag.
    while q and len(visited) < int(max_pages):
        url = q.popleft()
        url = _normalize_url(url)
        if url in visited:
            continue
        if not _same_domain(url, base):
            continue

        visited.add(url)

        if delay_sec and delay_sec > 0:
            time.sleep(float(delay_sec))

        fr = fetch_url(url, timeout=timeout, user_agent=user_agent, session=sess)

        page_row = {
            "url": url,
            "final_url": fr.final_url,
            "status_code": fr.status_code,
            "blocked": fr.blocked,
            "block_reason": fr.block_reason,
            "title": "",
            "meta_description": "",
            "meta_desc_len": 0,
            "canonical": "",
            "meta_robots": "",
            "viewport": "",
            "og_title": "",
            "og_description": "",
            "og_image": "",
            "h1_count": 0,
            "h1s": [],
            "top_h2": [],
            "total_images": 0,
            "images_with_alt": 0,
            "missing_title": False,
            "missing_meta": False,
            "missing_h1": False,
        }

        if not fr.blocked and fr.status_code == 200 and fr.text:
            parsed_data = parse_page(fr.text, fr.final_url or url)
            page_row.update({
                "title": parsed_data.get("title", ""),
                "meta_description": parsed_data.get("meta_description", ""),
                "meta_desc_len": len(_clean_text(parsed_data.get("meta_description", ""))),
                "canonical": parsed_data.get("canonical", ""),
                "meta_robots": parsed_data.get("meta_robots", ""),
                "viewport": parsed_data.get("viewport", ""),
                "og_title": parsed_data.get("og_title", ""),
                "og_description": parsed_data.get("og_description", ""),
                "og_image": parsed_data.get("og_image", ""),
                "h1_count": _safe_int(parsed_data.get("h1_count", 0)),
                "h1s": parsed_data.get("h1s", []),
                "top_h2": parsed_data.get("h2s", [])[:8],
                "total_images": _safe_int(parsed_data.get("total_images", 0)),
                "images_with_alt": _safe_int(parsed_data.get("images_with_alt", 0)),
            })

            # Missing signals
            page_row["missing_title"] = (_clean_text(page_row["title"]) == "")
            page_row["missing_meta"] = (_clean_text(page_row["meta_description"]) == "")
            page_row["missing_h1"] = (page_row["h1_count"] == 0)

            # Queue more internal links
            if len(visited) < int(max_pages):
                internal_links = parsed_data.get("internal_links", [])
                # limit to avoid exploding
                for nxt in internal_links[: max(10, links_per_page * 2)]:
                    if nxt not in visited:
                        q.append(nxt)

            # Link checks (optional)
            if check_internal_links:
                internal_links = parsed_data.get("internal_links", [])[: int(links_per_page)]
                for lk in internal_links:
                    lk_res = fetch_url(lk, timeout=timeout, user_agent=user_agent, session=sess)
                    cls = classify_link_status(lk_res.status_code, lk_res.blocked)
                    link_rows.append({
                        "from_url": fr.final_url or url,
                        "link_url": lk,
                        "status_code": lk_res.status_code,
                        "classification": cls,
                    })

        else:
            # blocked or non-200
            page_row["missing_title"] = True
            page_row["missing_meta"] = True
            page_row["missing_h1"] = True

        pages.append(page_row)

    pages_df = pd.DataFrame(pages)
    links_df = pd.DataFrame(link_rows) if link_rows else pd.DataFrame(columns=["from_url", "link_url", "status_code", "classification"])

    extras = {
        "base": base,
        "pages_crawled": len(pages_df),
    }
    return pages_df, links_df, extras


def classify_link_status(status_code: int, blocked: bool) -> str:
    if blocked:
        return "blocked"
    if status_code == 200:
        return "ok"
    if status_code in (301, 302, 307, 308):
        return "redirect"
    if status_code == 0:
        return "error"
    if status_code >= 400:
        return "broken"
    return "other"


# =========================
# Duplicates + Summaries
# =========================
def group_duplicates(series: pd.Series) -> Dict[str, List[str]]:
    """
    Returns dict: value -> list of URLs where value repeats, only for duplicates.
    """
    groups = defaultdict(list)
    for idx, val in series.items():
        v = _clean_text(val)
        if not v:
            continue
        groups[v].append(idx)
    return {k: v for k, v in groups.items() if len(v) > 1}

def compute_sitewide_counts(pages_df: pd.DataFrame) -> Dict[str, Any]:
    if pages_df is None or pages_df.empty:
        return {
            "pages_missing_title": 0,
            "pages_missing_meta": 0,
            "pages_missing_h1": 0,
            "duplicate_title_groups": {},
            "duplicate_meta_groups": {},
        }

    # duplicates keyed by final_url
    tmp = pages_df.set_index("final_url")

    dup_titles = group_duplicates(tmp.get("title", pd.Series(dtype=str)))
    dup_meta   = group_duplicates(tmp.get("meta_description", pd.Series(dtype=str)))


    return {
        "pages_missing_title": int(tmp["missing_title"].sum()),
        "pages_missing_meta": int(tmp["missing_meta"].sum()),
        "pages_missing_h1": int(tmp["missing_h1"].sum()),
        "duplicate_title_groups": dup_titles,
        "duplicate_meta_groups": dup_meta,
    }


# =========================
# Scoring (simple + stable)
# =========================
def grade_from_score(score: int) -> str:
    if score >= 85:
        return "Excellent"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Fair"
    return "Poor"

def score_homepage(home_row: Dict[str, Any], tech: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Rules-based homepage score + issues list.
    """
    issues = []
    score = 100

    if home_row.get("blocked"):
        return 0, [{
            "priority": "HIGH",
            "issue": "Request may be blocked or rate-limited",
            "why": "Homepage looks like a bot/WAF verification page. This prevents accurate auditing.",
            "how": "Reduce crawl intensity, increase delay, disable link checking, or run from a non-blocked IP."
        }]

    # Title
    if _clean_text(home_row.get("title")) == "":
        score -= 15
        issues.append({
            "priority": "HIGH",
            "issue": "Missing title tag",
            "why": "Title is a primary ranking and click signal.",
            "how": "Add a unique, descriptive title (50–60 chars)."
        })

    # Meta description
    md = _clean_text(home_row.get("meta_description"))
    if md == "":
        score -= 10
        issues.append({
            "priority": "MEDIUM",
            "issue": "Missing meta description",
            "why": "Meta descriptions affect SERP click-through and clarity.",
            "how": "Write a unique 140–160 char meta description with value proposition."
        })
    else:
        if len(md) < 80:
            score -= 4
            issues.append({
                "priority": "LOW",
                "issue": "Meta description too short",
                "why": "Too short may not communicate value in SERP.",
                "how": "Expand to ~140–160 chars, keep it natural."
            })
        if len(md) > 170:
            score -= 4
            issues.append({
                "priority": "LOW",
                "issue": "Meta description too long",
                "why": "Long descriptions can be truncated in SERPs.",
                "how": "Shorten to ~140–160 chars."
            })

    # H1
    h1_count = _safe_int(home_row.get("h1_count"))
    if h1_count == 0:
        score -= 12
        issues.append({
            "priority": "MEDIUM",
            "issue": "Missing H1",
            "why": "H1 clarifies the primary topic and helps structure content.",
            "how": "Add one clear H1 that matches the page intent."
        })
    elif h1_count > 1:
        score -= 3
        issues.append({
            "priority": "LOW",
            "issue": f"Multiple H1 tags ({h1_count})",
            "why": "Multiple H1s can dilute the primary topic signal.",
            "how": "Keep one primary H1; convert others to H2/H3."
        })

    # Canonical
    if _clean_text(home_row.get("canonical")) == "":
        score -= 3
        issues.append({
            "priority": "LOW",
            "issue": "Missing canonical tag",
            "why": "Canonical helps prevent duplicate content signals.",
            "how": "Add a canonical tag pointing to the preferred URL."
        })

    # Open Graph
    if _clean_text(home_row.get("og_title")) == "" or _clean_text(home_row.get("og_description")) == "":
        score -= 2
        issues.append({
            "priority": "LOW",
            "issue": "Open Graph tags missing or incomplete",
            "why": "OG tags improve link previews on social platforms.",
            "how": "Add og:title, og:description and ideally og:image in <head>."
        })

    # robots/sitemap
    if tech.get("robots_found") is False and not tech.get("robots_blocked"):
        score -= 4
        issues.append({
            "priority": "LOW",
            "issue": "robots.txt not found",
            "why": "Robots.txt helps communicate crawl directives to bots.",
            "how": "Add /robots.txt with correct directives and sitemap link."
        })

    return max(0, score), issues


def score_sitewide(site_counts: Dict[str, Any], pages_crawled: int) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Simple sitewide score based on issues found in crawl set.
    """
    if pages_crawled <= 0:
        return 0, []

    score = 100
    issues = []

    miss_h1 = site_counts.get("pages_missing_h1", 0)
    miss_title = site_counts.get("pages_missing_title", 0)
    miss_meta = site_counts.get("pages_missing_meta", 0)
    dup_titles = site_counts.get("duplicate_title_groups", {})
    dup_meta = site_counts.get("duplicate_meta_groups", {})

    # penalties are proportional
    score -= min(30, miss_title * 4)
    score -= min(25, miss_meta * 3)
    score -= min(25, miss_h1 * 3)
    score -= min(15, len(dup_titles) * 4)
    score -= min(10, len(dup_meta) * 3)

    if miss_h1 > 0:
        issues.append({
            "priority": "MEDIUM",
            "scope": "Sitewide",
            "issue": "Missing H1 across site",
            "why": "H1 clarifies page topic and helps structure content.",
            "how": "Add one clear H1 per page; avoid multiple H1s unless required."
        })
    if len(dup_titles) > 0:
        issues.append({
            "priority": "MEDIUM",
            "scope": "Sitewide",
            "issue": "Duplicate titles detected",
            "why": "Duplicate titles reduce differentiation in search results.",
            "how": "Rewrite titles to match each page intent (service/location/product/category)."
        })
    if len(dup_meta) > 0:
        issues.append({
            "priority": "LOW",
            "scope": "Sitewide",
            "issue": "Duplicate meta descriptions detected",
            "why": "Duplicates reduce uniqueness and can lower CTR relevance.",
            "how": "Write unique meta descriptions for key pages; start with top traffic pages."
        })

    return max(0, score), issues


# =========================
# AI Integration (OpenRouter)
# =========================
def openrouter_chat(
    *,
    api_key: str,
    model: str,
    messages: list,
    temperature: float = 0.2,
    max_tokens: int = 800,
    timeout: int = 30,
):
    if not api_key:
        return {"ok": False, "status": None, "error": "OPENROUTER_API_KEY missing", "raw": None, "text": None}

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "SEO Audit AI",
    }

    payload = {
        "model": model,
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
        "messages": messages,
    }

    # simple retry loop for AI
    for attempt in range(3):
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=timeout)
            raw = r.text

            # retry on rate limit / transient
            if r.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(1.0 + attempt * 1.5)
                continue

            if r.status_code != 200:
                return {"ok": False, "status": r.status_code, "error": raw[:800], "raw": raw, "text": None}

            data = r.json()
            text = data["choices"][0]["message"]["content"]
            return {"ok": True, "status": 200, "error": None, "raw": raw, "text": text}

        except requests.exceptions.Timeout:
            if attempt < 2:
                time.sleep(1.0 + attempt * 1.5)
                continue
            return {"ok": False, "status": None, "error": "Timeout contacting OpenRouter", "raw": None, "text": None}

        except Exception as e:
            return {"ok": False, "status": None, "error": str(e), "raw": None, "text": None}

    return {"ok": False, "status": None, "error": "Unknown OpenRouter error", "raw": None, "text": None}
    


def _safe_json_loads(txt: str):
    if not txt:
        return None

    # 1) direct
    try:
        return json.loads(txt)
    except Exception:
        pass

    # 2) strip code fences
    cleaned = re.sub(r"^```(?:json)?|```$", "", txt.strip(), flags=re.IGNORECASE | re.MULTILINE).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # 3) extract first JSON object/array from any surrounding text
    m = re.search(r"(\{.*\}|\[.*\])", cleaned, flags=re.DOTALL)
    if m:
        candidate = m.group(1).strip()
        try:
            return json.loads(candidate)
        except Exception:
            return None

    return None



def ai_page_suggestions(
    pages_df: pd.DataFrame,
    site_name: str = "",
    model: str = "google/gemma-3-27b-it:free",
    temperature: float = 0.2,
    max_pages: int = 8
) -> Dict[str, Dict[str, Any]]:

    if pages_df is None or pages_df.empty:
        return {}

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        return {"__error__": {"notes": "OPENROUTER_API_KEY is not set. Add it to your environment variables."}}

    df = pages_df.copy().head(int(max_pages))

    payload_pages = []
    for _, r in df.iterrows():
        payload_pages.append({
            "url": _clean_text(r.get("final_url") or r.get("url")),
            "path": urlparse(_clean_text(r.get("final_url") or r.get("url"))).path,
            "title": _clean_text(r.get("title")),
            "meta_description": _clean_text(r.get("meta_description")),
            "h1_count": _safe_int(r.get("h1_count")),
            "h1s": r.get("h1s") if isinstance(r.get("h1s"), list) else [],
            "top_h2": r.get("top_h2") if isinstance(r.get("top_h2"), list) else [],
            "canonical": _clean_text(r.get("canonical")),
            "status_code": _safe_int(r.get("status_code")),
            "blocked": bool(r.get("blocked")),
        })

    system = (
        "You are an SEO consultant. Generate recommendations ONLY from provided page fields. "
        "Do not invent products/services/locations. If information is insufficient, say so. "
        "Return STRICT JSON only. No markdown."
    )

    user = {
        "site_name": site_name,
        "rules": {
            "title": "unique, match intent from URL path/headings, 50–60 chars target, max 65, add brand at end if fits",
            "meta": "unique, 140–160 chars target, max 170, reflect on-page info only",
            "h1": "if missing, propose one clear H1 derived from headings/path"
        },
        "pages": payload_pages,
        "output_schema": {
            "pages": [
                {
                    "url": "string",
                    "title_suggested": "string or empty",
                    "meta_suggested": "string or empty",
                    "h1_suggested": "string or empty",
                    "notes": "string"
                }
            ]
        }
    }

    resp = openrouter_chat(
        api_key=api_key,
        model=model,
        temperature=temperature,
        max_tokens=1200,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user)}
        ],
    )

    if not resp.get("ok"):
        return {"__error__": {"notes": f"OpenRouter error ({resp.get('status')}): {resp.get('error')}"}}

    content = resp.get("text") or ""
    data = _safe_json_loads(content)
    if not data or "pages" not in data:
        return {"__error__": {"notes": "AI returned non-JSON or missing 'pages'. Try lowering temperature."}}

    out = {}
    for item in data.get("pages", []):
        u = _clean_text(item.get("url"))
        if not u:
            continue
        out[u] = {
            "title_suggested": _clean_text(item.get("title_suggested")),
            "meta_suggested": _clean_text(item.get("meta_suggested")),
            "h1_suggested": _clean_text(item.get("h1_suggested")),
            "notes": _clean_text(item.get("notes")),
        }
    return out


def ai_action_plan(
    homepage_issues: List[Dict[str, Any]],
    sitewide_issues: List[Dict[str, Any]],
    site_name: str = "",
    model: str = "google/gemma-3-27b-it:free",
    temperature: float = 0.2
) -> Dict[str, Any]:

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        return {"__error__": {"notes": "OPENROUTER_API_KEY is not set. Add it to your environment variables."}}

    system = (
        "You are an SEO consultant preparing a client-ready action plan. "
        "Stay grounded in the provided issues. Do not add new problems not listed. "
        "Return STRICT JSON only. No markdown."
    )

    user = {
        "site_name": site_name,
        "homepage_issues": homepage_issues,
        "sitewide_issues": sitewide_issues,
        "output_schema": {
            "executive_summary": "string",
            "quick_wins": ["string"],
            "roadmap": [
                {"label": "string (e.g., Week 1)", "items": ["string"]}
            ]
        }
    }

    resp = openrouter_chat(
        api_key=api_key,
        model=model,
        temperature=temperature,
        max_tokens=900,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user)}
        ],
    )

    if not resp.get("ok"):
        return {"__error__": {"notes": f"OpenRouter error ({resp.get('status')}): {resp.get('error')}"}}

    content = resp.get("text") or ""
    data = _safe_json_loads(content)
    return data if isinstance(data, dict) else {"__error__": {"notes": "AI returned non-JSON output."}}

def ai_seo_qa(
    *,
    question: str,
    site_name: str = "",
    model: str = "google/gemma-3-27b-it:free",
    temperature: float = 0.2,
    max_tokens: int = 700,
) -> Dict[str, Any]:
    """
    SEO-only Q&A assistant powered by OpenRouter.
    Returns:
      {"ok": True, "answer": "..."} or {"ok": False, "error": "..."}
    """
    q = _clean_text(question)
    if not q:
        return {"ok": False, "error": "Question is empty."}

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        return {"ok": False, "error": "OPENROUTER_API_KEY is not set."}

    system = (
        "You are an SEO expert assistant. Answer ONLY SEO-related questions. "
        "Be practical and precise. If user asks something outside SEO, say it’s outside scope. "
        "If user provides a website URL or brand context, tailor advice to it. "
        "Avoid inventing facts about the user's site."
    )

    user_msg = {
        "site_name": site_name,
        "question": q
    }

    resp = openrouter_chat(
        api_key=api_key,
        model=model,
        temperature=temperature,
        max_tokens=int(max_tokens),
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user_msg)}
        ],
    )

    if not resp.get("ok"):
        return {"ok": False, "error": f"OpenRouter error ({resp.get('status')}): {resp.get('error')}"}

    answer = _clean_text(resp.get("text") or "")
    return {"ok": True, "answer": answer}

def ai_seo_learning_answer(
    *,
    question: str,
    site_name: str = "",
    model: str = "google/gemma-3-27b-it:free",
    temperature: float = 0.2
) -> Dict[str, Any]:
    """
    SEO Learning Assistant: answers SEO-only questions in a structured JSON format.

    Returns STRICT JSON:
    {
      "ok": true/false,
      "scope": "seo" | "out_of_scope",
      "title": "string",
      "short_answer": "string",
      "key_points": ["string", ...],
      "step_by_step": ["string", ...],
      "checklist": ["string", ...],
      "examples": [{"title":"string","code":"string","language":"string"}],
      "warnings": ["string", ...],
      "sources_note": "string"
    }
    """
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        return {"__error__": {"notes": "OPENROUTER_API_KEY is not set. Add it to your environment variables."}}

    q = _clean_text(question)
    if not q:
        return {"ok": False, "scope": "out_of_scope", "title": "", "short_answer": "Please type a question."}

    system = (
    "You are an SEO Learning Assistant.\n"
    "You MUST answer ONLY SEO-related questions (technical SEO, on-page, indexing, sitemaps, metadata, "
    "structured data, Core Web Vitals, crawling, redirects, canonical, hreflang, internal linking).\n\n"

    "If the question is NOT SEO-related:\n"
    "- Set ok=false\n"
    "- Set scope='out_of_scope'\n"
    "- short_answer = ONE polite line\n"
    "- key_points, step_by_step, checklist, examples, warnings MUST be empty arrays\n\n"

    "OUTPUT FORMAT (STRICT):\n"
    "- Return STRICT JSON only. No markdown. No extra keys. No extra text.\n"
    "- Do NOT repeat content across fields.\n"
    "- Keep each section short:\n"
    "  short_answer: max 3-5 lines\n"
    "  key_points: 4-6 bullets\n"
    "  step_by_step: 4-8 steps\n"
    "  checklist: 6-10 checks\n"
    "  warnings: 0-6 bullets\n"
    "  examples: 0-2 items (only if needed)\n"
    "- Code must ONLY appear in examples[].code.\n"
    )


    user = {
        "site_name": site_name,
        "question": q,
        "output_schema": {
            "ok": "boolean",
            "scope": "seo | out_of_scope",
            "title": "string",
            "short_answer": "string",
            "key_points": ["string"],
            "step_by_step": ["string"],
            "checklist": ["string"],
            "examples": [{"title": "string", "code": "string", "language": "string"}],
            "warnings": ["string"],
            "sources_note": "string"
        }
    }

    resp = openrouter_chat(
        api_key=api_key,
        model=model,
        temperature=temperature,
        max_tokens=900,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user)}
        ],
    )

    if not resp.get("ok"):
        return {"__error__": {"notes": f"OpenRouter error ({resp.get('status')}): {resp.get('error')}"}}

    data = _safe_json_loads(resp.get("text") or "")

    def _dedupe_list(xs):
        if not isinstance(xs, list):
            return []
        out, seen = [], set()
        for x in xs:
            s = _clean_text(x)
            if not s:
                continue
            k = s.lower()
            if k in seen:
                continue
            seen.add(k)
            out.append(s)
        return out

    scope = _clean_text(data.get("scope")).lower()
    if scope not in ("seo", "out_of_scope"):
        scope = "seo"
    data["scope"] = scope

    if scope == "out_of_scope":
        data["ok"] = False
        data["key_points"] = []
        data["step_by_step"] = []
        data["checklist"] = []
        data["examples"] = []
        data["warnings"] = []
    else:
        data["ok"] = True
        data["key_points"] = _dedupe_list(data.get("key_points"))[:6]
        data["step_by_step"] = _dedupe_list(data.get("step_by_step"))[:8]
        data["checklist"] = _dedupe_list(data.get("checklist"))[:10]
        data["warnings"] = _dedupe_list(data.get("warnings"))[:6]

        # examples: normalize list of dicts
        ex = data.get("examples")
        if not isinstance(ex, list):
            ex = []
        cleaned = []
        for e in ex[:2]:
            if not isinstance(e, dict):
                continue
            cleaned.append({
                "title": _clean_text(e.get("title")),
                "code": e.get("code") if isinstance(e.get("code"), str) else "",
                "language": _clean_text(e.get("language")) or "text"
            })
        data["examples"] = cleaned


    if not isinstance(data, dict):
        return {"__error__": {"notes": "AI returned non-JSON output for learning assistant."}}

    # Minimal normalization
    data.setdefault("ok", True)
    data.setdefault("scope", "seo")
    data.setdefault("title", "")
    data.setdefault("short_answer", "")
    data.setdefault("key_points", [])
    data.setdefault("step_by_step", [])
    data.setdefault("checklist", [])
    data.setdefault("examples", [])
    data.setdefault("warnings", [])
    data.setdefault("sources_note", "General SEO guidance. Validate on your stack and Google documentation.")
    return data


def ai_implementation_code(
    *,
    site_name: str,
    target_language: str,
    fix_list: List[Dict[str, Any]],
    ai_suggestions: Dict[str, Any],
    model: str = "google/gemma-3-27b-it:free",
    temperature: float = 0.2
) -> Dict[str, Any]:
    """
    Generate code snippets for implementing the audit suggestions in a chosen tech stack.
    Returns STRICT JSON:
    {
      "items": [
        {
          "title": "string",
          "why": "string",
          "files": [{"path": "string", "code": "string"}],
          "notes": "string"
        }
      ]
    }
    """
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        return {"__error__": {"notes": "OPENROUTER_API_KEY is not set. Add it to your environment variables."}}

    # Keep prompt bounded (truncation is a big cause of broken JSON)
    fix_list_small = (fix_list or [])[:6]

    # Keep AI suggestions bounded too
    ai_sug_small: Dict[str, Any] = {}
    if isinstance(ai_suggestions, dict):
        # exclude error blobs + keep only a few keys
        keys = [k for k in ai_suggestions.keys() if k != "__error__"][:5]
        for k in keys:
            ai_sug_small[k] = ai_suggestions.get(k)

    system = (
        "You are a senior web developer + SEO engineer. "
        "Generate implementation code ONLY for the issues provided. "
        "Do NOT invent site features or routes. "
        "If a fix cannot be implemented safely without codebase context, give a minimal template + clear TODO notes. "
        "\n\n"
        "IMPORTANT OUTPUT RULES:\n"
        "- Return STRICT JSON ONLY (no markdown, no commentary).\n"
        "- DO NOT wrap code in ``` fences.\n"
        "- Put code as plain strings inside files[].code.\n"
        "- Use \\n for new lines inside code strings.\n"
        "- Ensure the JSON is valid and parseable.\n"
    )

    user = {
        "site_name": site_name,
        "target_language": target_language,
        "fix_list": fix_list_small,
        "ai_suggestions_sample": ai_sug_small,
        "rules": [
            "Prefer minimal, copy/pasteable code blocks.",
            "If Laravel: use Blade layout head section examples + Controller/middleware only if needed.",
            "If Next.js: show app/ or pages/ head metadata examples, and OpenGraph tags.",
            "If HTML: show <head> block examples.",
            "If WordPress: show functions.php hooks + theme header.php snippets.",
            "If Shopify Liquid: show theme.liquid head snippet.",
            "Always include canonical + title + meta description + og tags where relevant."
        ],
        "output_schema": {
            "items": [
                {
                    "title": "string",
                    "why": "string",
                    "files": [{"path": "string", "code": "string"}],
                    "notes": "string"
                }
            ]
        }
    }

    # Try twice:
    # 1) normal generation
    # 2) if invalid JSON, force the model to convert its own output into STRICT JSON
    last_text = ""
    for attempt in range(2):
        if attempt == 0:
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user)}
            ]
        else:
            messages = [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": (
                        "Convert the following response into STRICT VALID JSON that matches the schema. "
                        "Return JSON only. No markdown. No extra text.\n\n"
                        + (last_text or "")
                    )
                }
            ]

        resp = openrouter_chat(
            api_key=api_key,
            model=model,
            temperature=temperature,
            max_tokens=1400,
            messages=messages,
        )

        if not resp.get("ok"):
            return {"__error__": {"notes": f"OpenRouter error ({resp.get('status')}): {resp.get('error')}"}}

        last_text = resp.get("text") or ""
        data = _safe_json_loads(last_text)

        if isinstance(data, dict) and "items" in data:
            # minimal normalization (prevents missing keys from breaking UI)
            if not isinstance(data.get("items"), list):
                data["items"] = []
            for it in data["items"]:
                if isinstance(it, dict):
                    it.setdefault("title", "")
                    it.setdefault("why", "")
                    it.setdefault("files", [])
                    it.setdefault("notes", "")
                    if not isinstance(it.get("files"), list):
                        it["files"] = []
            return data

    return {
        "__error__": {
            "notes": "AI returned invalid JSON for implementation snippets.",
            "raw_preview": (last_text[:800] if last_text else "")
        }
    }


# =========================
# Reporting
# =========================
def build_markdown_report(result: Dict[str, Any]) -> str:
    """
    Create a client-ready markdown report from computed results.
    """
    url = result.get("final_url", "")
    home_score = result.get("homepage_score", 0)
    site_score = result.get("site_score", 0)
    http_status = result.get("http_status", "")
    tech = result.get("tech", {})
    home_issues = result.get("homepage_issues", [])
    fixlist = result.get("fix_list", [])  # merged list
    ai_plan = result.get("ai_plan", {})

    lines = []
    lines.append(f"# SEO Audit Report")
    lines.append("")
    lines.append(f"**Website:** {url}")
    lines.append(f"**HTTP Status:** {http_status}")
    lines.append(f"**Homepage Score:** {home_score} ({grade_from_score(home_score)})")
    lines.append(f"**Site Score:** {site_score} ({grade_from_score(site_score)})")
    lines.append("")

    lines.append("## Technical Checks")
    lines.append(f"- robots.txt: {'Found' if tech.get('robots_found') else 'Not found'} (status: {tech.get('robots_status')})")
    sm = tech.get("sitemaps", [])
    if sm:
        lines.append("- Sitemaps:")
        for x in sm:
            lines.append(f"  - {x.get('sitemap_url')} (status: {x.get('status')}, blocked: {x.get('blocked')})")
    lines.append("")

    lines.append("## Prioritised Fix List")
    if not fixlist:
        lines.append("- No major issues detected in the crawl set.")
    else:
        for i, it in enumerate(fixlist, start=1):
            lines.append(f"{i}. **[{it.get('priority','')}] {it.get('issue','')}**")
            lines.append(f"   - Why: {it.get('why','')}")
            lines.append(f"   - How: {it.get('how','')}")
    lines.append("")

    if ai_plan:
        lines.append("## AI Action Plan")
        if ai_plan.get("executive_summary"):
            lines.append(ai_plan.get("executive_summary"))
            lines.append("")
        if ai_plan.get("quick_wins"):
            lines.append("### Quick Wins")
            for q in ai_plan["quick_wins"]:
                lines.append(f"- {q}")
            lines.append("")
        if ai_plan.get("roadmap"):
            lines.append("### Roadmap")
            for step in ai_plan["roadmap"]:
                lines.append(f"**{step.get('label','')}**")
                for item in step.get("items", []):
                    lines.append(f"- {item}")
                lines.append("")

    lines.append("## Notes")
    lines.append("- This audit is based on an internal crawl sample and technical checks. For full coverage, increase crawl depth/pages and run again.")
    lines.append("")
    return "\n".join(lines)


# =========================
# Orchestrator
# =========================
def run_audit(
    url: str,
    timeout: int = 15,
    max_pages: int = 8,
    check_internal_links: bool = True,
    links_per_page: int = 8,
    delay_sec: float = 0.0,
    enable_ai: bool = False,
    ai_model: str = "google/gemma-3-27b-it:free",
    ai_temperature: float = 0.2,
    ai_max_pages: int = 8,
    site_name: str = "",
    ai_language: str = "Laravel (Blade)",
    ai_include_code: bool = False
) -> Dict[str, Any]:
    """
    Full pipeline for Phase 4:
    - crawl
    - technical checks
    - scoring + fix list
    - AI suggestions (optional)
    - markdown report
    """
    url = _normalize_url(url)

    # 1) Crawl
    pages_df, links_df, extras = crawl_site(
        start_url=url,
        max_pages=max_pages,
        timeout=timeout,
        user_agent=DEFAULT_UA,
        check_internal_links=check_internal_links,
        links_per_page=links_per_page,
        delay_sec=delay_sec
    )

    # 2) Technical
    tech = check_robots_and_sitemaps(url, timeout=timeout, user_agent=DEFAULT_UA)

    # Determine homepage row (first row is usually homepage)
    home_row = pages_df.iloc[0].to_dict() if not pages_df.empty else {"blocked": True}

    # 3) Sitewide stats + scoring
    site_counts = compute_sitewide_counts(pages_df)
    homepage_score, homepage_issues = score_homepage(home_row, tech)
    site_score, sitewide_issues = score_sitewide(site_counts, pages_crawled=extras.get("pages_crawled", 0))

    # 4) Build fix list (merged)
    fix_list = []

    # homepage issues first (already have priority)
    for it in homepage_issues:
        fix_list.append({
            "priority": it.get("priority", "LOW"),
            "scope": "Homepage",
            "issue": it.get("issue", ""),
            "why": it.get("why", ""),
            "how": it.get("how", ""),
        })

    # then sitewide issues
    for it in sitewide_issues:
        fix_list.append({
            "priority": it.get("priority", "LOW"),
            "scope": it.get("scope", "Sitewide"),
            "issue": it.get("issue", ""),
            "why": it.get("why", ""),
            "how": it.get("how", ""),
        })

    # Priority ordering
    priority_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    fix_list = sorted(fix_list, key=lambda x: priority_rank.get(x.get("priority", "LOW"), 9))

    # 5) AI (optional): page suggestions + action plan
    ai_suggestions = {}
    ai_plan = {}
    if enable_ai:
        try:
            ai_suggestions = ai_page_suggestions(
                pages_df=pages_df,
                site_name=site_name,
                model=ai_model,
                temperature=ai_temperature,
                max_pages=ai_max_pages
            )
        except Exception as e:
            ai_suggestions = {"__error__": {"notes": str(e)}}

        try:
            ai_plan = ai_action_plan(
                homepage_issues=homepage_issues,
                sitewide_issues=sitewide_issues,
                site_name=site_name,
                model=ai_model,
                temperature=ai_temperature
            )
        except Exception as e:
            ai_plan = {"executive_summary": "", "quick_wins": [], "roadmap": [], "error": str(e)}

    ai_implementation = {}

    if enable_ai and ai_include_code:
        try:
            ai_implementation = ai_implementation_code(
                site_name=site_name,
                target_language=ai_language,
                fix_list=fix_list,
                ai_suggestions=ai_suggestions,
                model=ai_model,
                temperature=ai_temperature
            )
        except Exception as e:
            ai_implementation = {"__error__": {"notes": str(e)}}


    # 6) report
    result = {
        "input_url": url,
        "final_url": home_row.get("final_url", url),
        "http_status": home_row.get("status_code", ""),
        "homepage_score": homepage_score,
        "site_score": site_score,
        "homepage_grade": grade_from_score(homepage_score) if homepage_score > 0 else "Blocked",
        "site_grade": grade_from_score(site_score),
        "tech": tech,
        "pages_df": pages_df,
        "links_df": links_df,
        "site_counts": site_counts,
        "homepage_issues": homepage_issues,
        "sitewide_issues": sitewide_issues,
        "fix_list": fix_list,
        "ai_suggestions": ai_suggestions,
        "ai_plan": ai_plan,
        "ai_implementation": ai_implementation,
    }

    result["report_md"] = build_markdown_report(result)
    return result
