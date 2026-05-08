#!/usr/bin/env python3
"""
SiteWatch Crawler
Crawls websites for broken links and forms, posts findings to the ingest endpoint.

Required env vars:
  CRAWLER_INGEST_SECRET  — bearer token (set in GitHub Actions secrets)

Optional env vars:
  INGEST_URL             — override the default endpoint URL
"""

import os
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
import time
from datetime import datetime, timezone

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

MAX_PAGES_PER_SITE = 150
REQUEST_DELAY      = 0.4    # seconds between requests
TIMEOUT            = 15

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "#", "data:", "sms:", "whatsapp:")

# Words in visible text that indicate a CTA (high severity)
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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def head_check(url: str, session: requests.Session):
    """Return (status_code, error_string). Falls back from HEAD to GET on 405."""
    try:
        r = session.head(url, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code == 405:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
            r.close()
        return r.status_code, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL error: {str(e)[:120]}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection error: {str(e)[:120]}"
    except requests.exceptions.Timeout:
        return None, "Timeout"
    except Exception as e:
        return None, str(e)[:120]


# ---------------------------------------------------------------------------
# Issue classification
# ---------------------------------------------------------------------------

def get_section_hint(tag) -> str:
    """Walk up the DOM to find which section the element lives in."""
    for parent in tag.parents:
        name = getattr(parent, "name", None)
        if name in ("header",):
            return "Header"
        if name in ("nav",):
            return "Navigation"
        if name in ("footer",):
            return "Footer"
        if name in ("form",):
            return "Form"
        if name in ("aside",):
            return "Sidebar"
        if name in ("main", "article", "section"):
            return "Main content"
    return "Main content"


def get_element_type(tag, section_hint: str, visible_text: str) -> str:
    """Classify what kind of element this is."""
    tag_name = tag.name if tag else "a"
    text_lower = visible_text.lower()

    if tag_name in ("button",) or (
        tag_name == "input" and tag.get("type") in ("submit", "button")
    ):
        return "Form submit"

    if section_hint in ("Header", "Navigation"):
        return "Navigation link"

    if section_hint == "Footer":
        return "Footer link"

    # Check for button-like classes
    classes = " ".join(tag.get("class", [])).lower() if tag else ""
    if any(w in classes for w in ("btn", "button", "cta")):
        return "CTA button"

    # Check visible text for CTA keywords
    if any(kw in text_lower for kw in CTA_KEYWORDS):
        return "CTA button"

    # Image link
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
    if status == 403:
        return "broken_link"
    return "broken_link"


def get_severity(element_type: str, issue_type: str, page_url: str, broken_url: str) -> str:
    url_lower = (page_url + " " + (broken_url or "")).lower()

    # Critical: checkout/cart/order forms or server errors on key pages
    if issue_type in ("broken_form", "server_error"):
        if any(w in url_lower for w in ("cart", "checkout", "order", "payment", "contact")):
            return "critical"

    if element_type == "Form submit":
        return "critical"

    if element_type == "CTA button":
        return "high"

    if element_type in ("Navigation link",):
        return "medium"

    if element_type in ("Footer link",):
        return "low"

    return "medium"


def get_plain_english(visible_text: str, element_type: str, page_title: str,
                       issue_type: str, http_status, error: str) -> str:
    elem = element_type.lower()
    text_part = f'"{visible_text}"' if visible_text and visible_text != "[no text]" else f"A {elem}"
    page_part = f'the "{page_title}" page' if page_title else "a page"

    if issue_type == "broken_link":
        problem = "links to a page that no longer exists"
    elif issue_type == "broken_form":
        problem = "submits to an endpoint that isn't responding — the form won't work"
    elif issue_type == "server_error":
        problem = f"is hitting a server error ({http_status}) — something broke on the backend"
    elif issue_type == "ssl_error":
        problem = "has a security certificate issue — browsers may block it"
    elif issue_type == "timeout":
        problem = "didn't respond in time — the destination may be down"
    elif issue_type == "unreachable":
        problem = "points to a site that can't be reached"
    elif issue_type == "empty_destination":
        problem = "has no destination — it does nothing when clicked"
    else:
        problem = f"is broken (HTTP {http_status or 'error'})"

    return f"The {text_part} {elem} on {page_part} {problem}."


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

def crawl_site(base_url: str) -> dict:
    session = requests.Session()
    session.headers.update(HEADERS)

    visited: set       = set()
    queue: deque       = deque([base_url])
    checked_external   = {}   # url -> (status, error)
    findings           = []
    pages_crawled      = 0
    started_at         = now_iso()

    print(f"\n{'='*65}")
    print(f"  Crawling: {base_url}")
    print(f"{'='*65}")

    while queue and pages_crawled < MAX_PAGES_PER_SITE:
        url = queue.popleft()
        norm = normalize(url)

        if norm in visited:
            continue
        visited.add(norm)

        print(f"  [{pages_crawled + 1:>3}] {url[:90]}")

        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            pages_crawled += 1
        except Exception as e:
            pages_crawled += 1
            time.sleep(REQUEST_DELAY)
            continue

        if "text/html" not in resp.headers.get("content-type", ""):
            time.sleep(REQUEST_DELAY)
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        page_title = (soup.find("title") or soup.new_tag("title")).get_text(strip=True)[:120]

        # --- <a href> links ---
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if any(href.startswith(s) for s in SKIP_SCHEMES):
                continue

            full = urljoin(url, href)
            if not crawlable(full):
                continue

            norm_full  = normalize(full)
            visible    = (tag.get_text(strip=True) or tag.get("aria-label", "") or "[no text]")[:80]
            section    = get_section_hint(tag)
            elem_type  = get_element_type(tag, section, visible)

            if same_domain(full, base_url):
                if norm_full not in visited:
                    queue.append(full)
                # Still check internal links for 4xx/5xx
                if norm_full not in checked_external:
                    status, error = head_check(full, session)
                    checked_external[norm_full] = (status, error)
                    time.sleep(REQUEST_DELAY)
                else:
                    status, error = checked_external[norm_full]
            else:
                if norm_full not in checked_external:
                    checked_external[norm_full] = head_check(full, session)
                    time.sleep(REQUEST_DELAY)
                status, error = checked_external[norm_full]

            if status is None or status >= 400:
                issue_type = get_issue_type(status, error or "", is_form=False)
                severity   = get_severity(elem_type, issue_type, url, full)
                findings.append({
                    "severity":     severity,
                    "issue_type":   issue_type,
                    "page_url":     url,
                    "page_title":   page_title,
                    "section_hint": section,
                    "element_type": elem_type,
                    "visible_text": visible,
                    "broken_url":   full,
                    "http_status":  status,
                    "plain_english": get_plain_english(
                        visible, elem_type, page_title, issue_type, status, error or ""
                    ),
                })

        # --- <form> actions ---
        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip()
            if not action or any(action.startswith(s) for s in SKIP_SCHEMES):
                continue

            full_action = urljoin(url, action)
            if not crawlable(full_action):
                continue

            norm_action = normalize(full_action)
            if norm_action not in checked_external:
                checked_external[norm_action] = head_check(full_action, session)
                time.sleep(REQUEST_DELAY)
            status, error = checked_external[norm_action]

            if status is None or status >= 400:
                section   = get_section_hint(form)
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
                    "severity":     severity,
                    "issue_type":   issue_type,
                    "page_url":     url,
                    "page_title":   page_title,
                    "section_hint": section,
                    "element_type": "Form submit",
                    "visible_text": visible,
                    "broken_url":   full_action,
                    "http_status":  status,
                    "plain_english": get_plain_english(
                        visible, "Form submit", page_title, issue_type, status, error or ""
                    ),
                })

        time.sleep(REQUEST_DELAY)

    completed_at = now_iso()
    print(f"       Pages: {pages_crawled}  |  Findings: {len(findings)}")

    return {
        "site":          urlparse(base_url).netloc,   # e.g. "israelpharm.com"
        "pages_crawled": pages_crawled,
        "started_at":    started_at,
        "completed_at":  completed_at,
        "findings":      findings,
    }


# ---------------------------------------------------------------------------
# Post to ingest endpoint
# ---------------------------------------------------------------------------

def post_to_ingest(payload: dict, secret: str) -> bool:
    site = payload["site"]
    findings_count = len(payload["findings"])
    print(f"  Posting {findings_count} finding(s) for {site} → {INGEST_URL}")

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
            print(f"  ✓ scan_id={data.get('scan_id')}  inserted={data.get('inserted')}  skipped={data.get('skipped_duplicates')}")
            return True
        else:
            print(f"  ✗ HTTP {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"  ✗ Request failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    secret = os.environ.get("CRAWLER_INGEST_SECRET", "").strip()
    if not secret:
        print("ERROR: CRAWLER_INGEST_SECRET env var is not set.")
        sys.exit(1)

    success_count = 0
    for site_url in SITES:
        payload = crawl_site(site_url)
        if post_to_ingest(payload, secret):
            success_count += 1

    print(f"\n{'='*65}")
    print(f"  Done. {success_count}/{len(SITES)} sites posted successfully.")
    print(f"{'='*65}\n")

    if success_count < len(SITES):
        sys.exit(1)
