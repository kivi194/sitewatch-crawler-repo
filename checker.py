#!/usr/bin/env python3
"""
SiteWatch Crawler
Crawls websites for broken links and forms, posts findings to the ingest endpoint.

Required env vars:
  CRAWLER_INGEST_SECRET  -- bearer token (set in GitHub Actions secrets)

Optional env vars:
  INGEST_URL             -- override the default endpoint URL
"""

import os
import sys
import base64
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time
from datetime import datetime, timezone

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

INGEST_URL = os.environ.get(
    "INGEST_URL",
    "https://anchor-watcher.lovable.app/api/public/crawler/ingest"
)

SITES = [
    "https://israelpharm.com",
    "https://www.rxfor.me/",
    "http://reekooz.com/",
]

MAX_PAGES_PER_SITE      = 200
REQUEST_DELAY           = 0.3   # seconds between page GETs (be polite)
TIMEOUT                 = 15
EXTERNAL_CHECK_WORKERS  = 10    # concurrent threads for external link checks
RETRY_ON_ERROR          = 1     # retries for transient failures

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "#", "data:", "sms:", "whatsapp:")

# URL path segments that are never useful to crawl or check
SKIP_PATH_SEGMENTS = (
    "cdn-cgi",      # Cloudflare (email obfuscation, etc.)
    "wp-json",      # WordPress REST API
    "wp-admin",     # WordPress admin
    "xmlrpc.php",   # WordPress XML-RPC
    "feed",         # RSS feeds
    ".xml",         # XML files (handled via sitemap separately)
    ".pdf", ".zip", ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".mp4", ".mp3", ".webp", ".ico", ".woff", ".woff2", ".ttf",
)

CTA_KEYWORDS = {
    "buy", "order", "purchase", "add to cart", "checkout", "contact",
    "get started", "sign up", "subscribe", "book", "reserve", "request",
    "apply", "register", "download", "get quote", "try", "start",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize(url: str) -> str:
    url, _ = urldefrag(url)
    return url.rstrip("/")


def same_domain(url: str, base: str) -> bool:
    return urlparse(url).netloc == urlparse(base).netloc


def crawlable(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def should_skip(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(seg in path for seg in SKIP_PATH_SEGMENTS)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def head_check(url: str, session: requests.Session, retries: int = RETRY_ON_ERROR):
    """HEAD check with GET fallback on 405. Retries once on transient errors."""
    for attempt in range(retries + 1):
        try:
            r = session.head(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 405:
                r = session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
                r.close()
            # Retry on 503/429 (server overloaded / rate limited)
            if r.status_code in (429, 503) and attempt < retries:
                time.sleep(2)
                continue
            return r.status_code, None
        except requests.exceptions.SSLError as e:
            return None, f"SSL error: {str(e)[:100]}"
        except requests.exceptions.ConnectionError as e:
            if attempt < retries:
                time.sleep(1)
                continue
            return None, f"Connection error: {str(e)[:100]}"
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(1)
                continue
            return None, "Timeout"
        except Exception as e:
            return None, str(e)[:100]
    return None, "Failed after retries"


# ---------------------------------------------------------------------------
# Sitemap discovery
# ---------------------------------------------------------------------------

SITEMAP_PATHS = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
                 "/wp-sitemap.xml", "/page-sitemap.xml", "/post-sitemap.xml"]


def fetch_sitemap_urls(base_url: str, session: requests.Session) -> list:
    """Try common sitemap paths and extract all <loc> URLs for the same domain."""
    found = []
    for path in SITEMAP_PATHS:
        try:
            r = session.get(base_url.rstrip("/") + path, timeout=10, allow_redirects=True)
            if r.status_code != 200 or "xml" not in r.headers.get("content-type", ""):
                continue
            soup = BeautifulSoup(r.text, "xml")
            # sitemap index — contains <sitemap><loc> pointing to child sitemaps
            for sitemap_tag in soup.find_all("sitemap"):
                loc = sitemap_tag.find("loc")
                if loc:
                    child = fetch_sitemap_urls(loc.text.strip(), session)
                    found.extend(child)
            # regular sitemap — contains <url><loc>
            for url_tag in soup.find_all("url"):
                loc = url_tag.find("loc")
                if loc:
                    u = loc.text.strip()
                    if same_domain(u, base_url):
                        found.append(u)
            if found:
                print(f"    Sitemap found at {path}: {len(found)} URLs")
                break
        except Exception:
            continue
    return found


# ---------------------------------------------------------------------------
# Issue classification
# ---------------------------------------------------------------------------

def get_section_hint(tag) -> str:
    for parent in tag.parents:
        name = getattr(parent, "name", None)
        if name == "header":
            return "Header"
        if name == "nav":
            return "Navigation"
        if name == "footer":
            return "Footer"
        if name == "form":
            return "Form"
        if name == "aside":
            return "Sidebar"
        if name in ("main", "article", "section"):
            return "Main content"
    return "Main content"


def get_element_type(tag, section_hint: str, visible_text: str) -> str:
    tag_name = tag.name if tag else "a"
    text_lower = visible_text.lower()

    if tag_name == "button" or (
        tag_name == "input" and tag.get("type") in ("submit", "button")
    ):
        return "Form submit"

    if section_hint in ("Header", "Navigation"):
        return "Navigation link"

    if section_hint == "Footer":
        return "Footer link"

    classes = " ".join(tag.get("class", [])).lower() if tag else ""
    if any(w in classes for w in ("btn", "button", "cta")):
        return "CTA button"

    if any(kw in text_lower for kw in CTA_KEYWORDS):
        return "CTA button"

    if tag and tag.find("img"):
        return "Image link"

    return "Content link"


def get_issue_type(status, error: str, is_form: bool) -> str:
    if is_form:
        return "broken_form"
    if error:
        err = error.lower()
        if "ssl" in err:
            return "ssl_error"
        if "timeout" in err:
            return "timeout"
        return "unreachable"
    if status == 404:
        return "broken_link"
    if status and status >= 500:
        return "server_error"
    return "broken_link"


def get_severity(element_type: str, issue_type: str, page_url: str, broken_url: str) -> str:
    url_lower = (page_url + " " + (broken_url or "")).lower()

    if element_type == "Form submit":
        return "critical"

    if issue_type in ("broken_form", "server_error"):
        if any(w in url_lower for w in ("cart", "checkout", "order", "payment", "contact")):
            return "critical"

    if element_type == "CTA button":
        return "high"

    if element_type == "Navigation link":
        return "medium"

    if element_type == "Footer link":
        return "low"

    return "medium"


def get_plain_english(visible_text: str, element_type: str, page_title: str,
                      issue_type: str, http_status, error: str) -> str:
    elem = element_type.lower()
    text_part = f'"{visible_text}"' if visible_text and visible_text != "[no text]" else f"A {elem}"
    page_part = f'the "{page_title}" page' if page_title else "a page"

    problems = {
        "broken_link":        "links to a page that no longer exists",
        "broken_form":        "submits to an endpoint that isn't responding — the form won't work",
        "server_error":       f"is hitting a server error ({http_status}) — something broke on the backend",
        "ssl_error":          "has a security certificate issue — browsers may block it",
        "timeout":            "didn't respond in time — the destination may be down",
        "unreachable":        "points to a site that can't be reached",
        "empty_destination":  "has no destination — it does nothing when clicked",
    }
    problem = problems.get(issue_type, f"is broken (HTTP {http_status or 'error'})")
    return f"The {text_part} {elem} on {page_part} {problem}."


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

def crawl_site(base_url: str, secret: str = "") -> dict:
    session = requests.Session()
    session.headers.update(HEADERS)

    visited: set     = set()
    queue: deque     = deque()
    checked          = {}          # url -> (status, error)  shared check cache
    checked_lock     = Lock()
    findings         = []
    pages_crawled    = 0
    started_at       = now_iso()

    print(f"\n{'='*65}")
    print(f"  Crawling: {base_url}")
    print(f"{'='*65}")

    # Seed queue from sitemap first, then homepage
    sitemap_urls = fetch_sitemap_urls(base_url, session)
    for u in sitemap_urls:
        queue.append(u)
    queue.appendleft(base_url)   # homepage always first

    def check_url(url: str):
        """Thread-safe cached URL check."""
        norm = normalize(url)
        with checked_lock:
            if norm in checked:
                return checked[norm]
        result = head_check(url, session)
        with checked_lock:
            checked[norm] = result
        return result

    while queue and pages_crawled < MAX_PAGES_PER_SITE:
        url = queue.popleft()
        norm = normalize(url)

        if norm in visited or should_skip(url):
            continue
        visited.add(norm)

        print(f"  [{pages_crawled + 1:>3}] {url[:90]}")

        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            pages_crawled += 1
        except Exception:
            pages_crawled += 1
            time.sleep(REQUEST_DELAY)
            continue

        # Mark GET status so we don't re-check this URL as an external link
        with checked_lock:
            checked[norm] = (resp.status_code, None)

        if "text/html" not in resp.headers.get("content-type", ""):
            time.sleep(REQUEST_DELAY)
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        page_title = soup.find("title")
        page_title = page_title.get_text(strip=True)[:120] if page_title else urlparse(url).path or base_url

        # Collect links to process
        links_to_check = []   # (full_url, tag, is_external)

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if any(href.startswith(s) for s in SKIP_SCHEMES):
                continue
            full = urljoin(url, href)
            if not crawlable(full) or should_skip(full):
                continue
            norm_full = normalize(full)
            if same_domain(full, base_url):
                if norm_full not in visited:
                    queue.append(full)
                # Only report internal broken links, skip if we'll crawl it
                # (crawl will capture actual status on the GET)
            else:
                links_to_check.append((full, tag, True))

        # Check external links concurrently
        external_urls = list({normalize(u): (u, tag) for u, tag, _ in links_to_check}.values())

        def check_and_return(item):
            full, tag = item
            status, error = check_url(full)
            return full, tag, status, error

        with ThreadPoolExecutor(max_workers=EXTERNAL_CHECK_WORKERS) as pool:
            futures = {pool.submit(check_and_return, item): item for item in external_urls}
            for future in as_completed(futures):
                full, tag, status, error = future.result()
                if status is None or status >= 400:
                    visible   = (tag.get_text(strip=True) or tag.get("aria-label", "") or "[no text]")[:80]
                    section   = get_section_hint(tag)
                    elem_type = get_element_type(tag, section, visible)
                    issue_type = get_issue_type(status, error or "", is_form=False)
                    severity   = get_severity(elem_type, issue_type, url, full)
                    findings.append({
                        "severity":      severity,
                        "issue_type":    issue_type,
                        "page_url":      url,
                        "page_title":    page_title,
                        "section_hint":  section,
                        "element_type":  elem_type,
                        "visible_text":  visible,
                        "broken_url":    full,
                        "http_status":   status,
                        "plain_english": get_plain_english(
                            visible, elem_type, page_title, issue_type, status, error or ""
                        ),
                    })

        # Check form actions
        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip()
            if not action or any(action.startswith(s) for s in SKIP_SCHEMES):
                continue
            full_action = urljoin(url, action)
            if not crawlable(full_action) or should_skip(full_action):
                continue

            status, error = check_url(full_action)
            if status is None or status >= 400:
                section    = get_section_hint(form)
                issue_type = get_issue_type(status, error or "", is_form=True)
                severity   = get_severity("Form submit", issue_type, url, full_action)
                submit_btn = form.find(["button", "input"], {"type": ["submit", "button"]})
                visible    = ""
                if submit_btn:
                    visible = (
                        submit_btn.get_text(strip=True)
                        or submit_btn.get("value", "")
                        or submit_btn.get("aria-label", "")
                    )[:80]
                visible = visible or "Submit"
                findings.append({
                    "severity":      severity,
                    "issue_type":    issue_type,
                    "page_url":      url,
                    "page_title":    page_title,
                    "section_hint":  section,
                    "element_type":  "Form submit",
                    "visible_text":  visible,
                    "broken_url":    full_action,
                    "http_status":   status,
                    "plain_english": get_plain_english(
                        visible, "Form submit", page_title, issue_type, status, error or ""
                    ),
                })

        # Take one screenshot for this page if it has findings, attach to all of them
        page_findings = [f for f in findings if f["page_url"] == url and "screenshot_url" not in f]
        if page_findings and PLAYWRIGHT_AVAILABLE:
            print(f"       Taking screenshot of {url[:70]}")
            img_b64 = take_screenshot(url)
            if img_b64:
                shot_url = upload_screenshot(url, img_b64, secret)
                if shot_url:
                    for f in page_findings:
                        f["screenshot_url"] = shot_url

        time.sleep(REQUEST_DELAY)

    completed_at = now_iso()
    print(f"       Pages: {pages_crawled}  |  Findings: {len(findings)}")

    return {
        "site":          urlparse(base_url).netloc,
        "pages_crawled": pages_crawled,
        "started_at":    started_at,
        "completed_at":  completed_at,
        "findings":      findings,
    }


# ---------------------------------------------------------------------------
# Screenshot capture + upload
# ---------------------------------------------------------------------------

def take_screenshot(url: str) -> str | None:
    """Navigate to a page with Playwright and return a base64 JPEG screenshot."""
    if not PLAYWRIGHT_AVAILABLE:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(url, wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(1500)   # let lazy-loaded content settle
            img_bytes = page.screenshot(type="jpeg", quality=75, full_page=False)
            browser.close()
        return base64.b64encode(img_bytes).decode("utf-8")
    except Exception as e:
        print(f"    Screenshot failed for {url}: {e}")
        return None


def upload_screenshot(page_url: str, image_base64: str, secret: str) -> str | None:
    """Upload a base64 screenshot to Lovable and return the public URL."""
    upload_url = INGEST_URL.replace("/crawler/ingest", "/crawler/upload-screenshot")
    try:
        resp = requests.post(
            upload_url,
            json={
                "page_url":     page_url,
                "image_base64": image_base64,
                "mime_type":    "image/jpeg",
            },
            headers={
                "Authorization": f"Bearer {secret}",
                "Content-Type":  "application/json",
            },
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json().get("screenshot_url")
        else:
            print(f"    Screenshot upload failed: HTTP {resp.status_code}")
            return None
    except Exception as e:
        print(f"    Screenshot upload error: {e}")
        return None


# ---------------------------------------------------------------------------
# Post to ingest endpoint
# ---------------------------------------------------------------------------

def post_to_ingest(payload: dict, secret: str) -> bool:
    site           = payload["site"]
    findings_count = len(payload["findings"])
    print(f"  Posting {findings_count} finding(s) for {site} -> {INGEST_URL}")
    try:
        resp = requests.post(
            INGEST_URL,
            json=payload,
            headers={
                "Authorization": f"Bearer {secret}",
                "Content-Type":  "application/json",
            },
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            print(f"  OK scan_id={data.get('scan_id')}  inserted={data.get('inserted')}  skipped={data.get('skipped_duplicates')}")
            return True
        else:
            print(f"  FAIL HTTP {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"  FAIL Request failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    secret = os.environ.get("CRAWLER_INGEST_SECRET", "").strip()
    if not secret:
        print("ERROR: CRAWLER_INGEST_SECRET env var is not set.")
        sys.exit(1)

    # Crawl all 3 sites in parallel
    from concurrent.futures import ThreadPoolExecutor as SitePool
    results = []
    with SitePool(max_workers=len(SITES)) as pool:
        futures = {pool.submit(crawl_site, url, secret): url for url in SITES}
        for future in as_completed(futures):
            results.append(future.result())

    # Post results sequentially (no need to hammer the ingest endpoint)
    success_count = 0
    for payload in results:
        if post_to_ingest(payload, secret):
            success_count += 1

    print(f"\n{'='*65}")
    print(f"  Done. {success_count}/{len(SITES)} sites posted successfully.")
    print(f"{'='*65}\n")

    if success_count < len(SITES):
        sys.exit(1)
