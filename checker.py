#!/usr/bin/env python3
"""
SiteWatch Crawler
Crawls websites for broken links and forms, posts findings to the ingest endpoint.

Required env vars:
  CRAWLER_INGEST_SECRET  -- bearer token (set in GitHub Actions secrets)

Optional env vars:
  INGEST_URL             -- override the default endpoint URL
"""

import argparse
import os
import sys
import re
import base64
import hashlib
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

# Per-site config: base_url + priority pages to always check first
SITE_CONFIG = [
    {
        "base_url": "https://israelpharm.com",
        "priority_urls": [
            "https://israelpharm.com/",
            # NOTE: /shop/, /cart/, /checkout/ are blocked by Cloudflare Access.
            # Whitelist GitHub Actions IPs in Cloudflare to enable crawling these pages.
        ],
    },
    {
        "base_url": "https://www.rxfor.me",
        "priority_urls": [
            "https://www.rxfor.me/",
            "https://www.rxfor.me/treatments/",
            "https://www.rxfor.me/treatments/weight-loss",
            "https://www.rxfor.me/treatments/ed-treatment",
            "https://www.rxfor.me/treatments/testosterone-men",
            "https://www.rxfor.me/treatments/testosterone-women",
            "https://www.rxfor.me/treatments/hair-loss",
            "https://www.rxfor.me/treatments/prescription-renewal",
            "https://www.rxfor.me/auth",           # consult flow entry
            "https://www.rxfor.me/about",
            "https://www.rxfor.me/cart",
            "https://www.rxfor.me/checkout",
        ],
    },
    {
        "base_url": "https://www.reekooz.com",
        "priority_urls": [
            "https://www.reekooz.com/",
            "https://www.reekooz.com/shop/",
            # Key products
            "https://www.reekooz.com/product/zoomind/",
            "https://www.reekooz.com/product/nowonder-nasal-cleanser/",
            "https://www.reekooz.com/product/enovid-nitric-oxide-spray/",
            "https://www.reekooz.com/product/nasodine/",
            "https://www.reekooz.com/product/phyllotex/",
            # Vitamin packs
            "https://www.reekooz.com/product/immune-pack/",
            "https://www.reekooz.com/product/allergy-pack/",
            "https://www.reekooz.com/product/healthy-weight-pack/",
            "https://www.reekooz.com/product/sleep-pack/",
            "https://www.reekooz.com/product/stress-pack/",
            "https://www.reekooz.com/product/energy-pack/",
            "https://www.reekooz.com/product/his-essentials/",
            "https://www.reekooz.com/product/her-essentials/",
            "https://www.reekooz.com/product/longevity-pack/",
            "https://www.reekooz.com/product/bone-health-pack/",
            "https://www.reekooz.com/product/gut-pack/",
            # Support pages
            "https://www.reekooz.com/faq/",
            "https://www.reekooz.com/faq/zoomind/",
            "https://www.reekooz.com/faq/enovid/",
            "https://www.reekooz.com/about-us/",
            "https://www.reekooz.com/contact-us/",
            "https://www.reekooz.com/cart/",
            "https://www.reekooz.com/checkout/",
        ],
    },
]

# Flat list for entry point
SITES = [s["base_url"] for s in SITE_CONFIG]
PRIORITY_URLS = {s["base_url"]: s["priority_urls"] for s in SITE_CONFIG}

# ---------------------------------------------------------------------------
# Priority transaction test definitions
# ---------------------------------------------------------------------------
# Each entry is a list of tests for a site.
# Fields:
#   name          — human-readable label shown in logs and used as section_hint
#   url           — page to load
#   url_rotation  — list of URLs; one is picked per ISO week number (mutually exclusive with url)
#   wait_for      — CSS selector to wait for before running checks (optional)
#   checks        — list of element visibility/state assertions (see below)
#   actions       — optional interaction steps (click, fill) with post-action assertions
#
# Check fields:
#   selector  — CSS selector (Playwright picks the first match)
#   label     — human-readable element name used in finding messages
#   severity  — "critical" | "high"
#   check     — "visible" (default) | "enabled" (also implies visible)
#
# Action fields:
#   type      — "click" | "fill"
#   selector  — element to interact with
#   label     — human-readable label
#   value     — text to type (fill only)
#   wait_ms   — ms to wait after action (default 3000 for click, 500 for fill)
#   severity  — severity if this action fails
#   assert    — optional post-action assertion:
#                 selector, check ("visible" | "url_contains"), value (url_contains), label, severity
#
# NOTE: Add real product slugs for israelpharm.com in url_rotation once known.
#       Reekooz and rxfor.me slugs are already stable.

_WEEK_NUM = datetime.now(timezone.utc).isocalendar()[1]

PRIORITY_TESTS = {
    # ── IsraelPharm ──────────────────────────────────────────────────────────
    "https://israelpharm.com": [
        {
            "name": "Home page core elements",
            "url": "https://israelpharm.com/",
            "wait_for": "body",
            "checks": [
                {"selector": "header, .site-header, #masthead",
                 "label": "Page header", "severity": "high"},
                {"selector": "nav, .nav-menu, .main-navigation, #site-navigation, #primary-menu",
                 "label": "Main navigation", "severity": "critical"},
                {"selector": ".logo img, .site-logo, .custom-logo, header img",
                 "label": "Header logo", "severity": "high"},
                {"selector": (
                    "a[href*='shop'], a[href*='catalog'], a[href*='product'], "
                    ".shop-link, .woocommerce-loop-product__link"
                 ),
                 "label": "Shop / product link", "severity": "high"},
            ],
        },
        {
            "name": "Menu navigation links",
            "url": "https://israelpharm.com/",
            "wait_for": "nav, #site-navigation",
            "checks": [
                {"selector": "nav a, .nav-menu a, #primary-menu a",
                 "label": "Navigation anchor links", "severity": "high"},
            ],
        },
        {
            "name": "Shop / category listing",
            # /shop/ may be blocked by Cloudflare — page_load_failed finding is expected in that case
            "url": "https://israelpharm.com/shop/",
            "wait_for": "body",
            "checks": [
                {"selector": "ul.products, .products, .woocommerce-loop-product, li.product",
                 "label": "Product grid", "severity": "critical"},
            ],
        },
        {
            # Rotate through product category pages weekly.
            # TODO: replace with direct /product/<slug>/ URLs once product catalog is stable.
            "name": "Product category page (weekly rotation)",
            "url_rotation": [
                "https://israelpharm.com/product-category/vitamins/",
                "https://israelpharm.com/product-category/beauty/",
                "https://israelpharm.com/product-category/supplements/",
                "https://israelpharm.com/product-category/baby/",
            ],
            "wait_for": "body",
            "checks": [
                {"selector": "ul.products, li.product, .woocommerce-loop-product__link",
                 "label": "Products in category", "severity": "high"},
                {"selector": "h1, .woocommerce-products-header__title",
                 "label": "Category title", "severity": "medium"},
            ],
        },
        {
            "name": "Checkout form presence",
            # Cloudflare may block this — finding will show page_load_failed (expected)
            "url": "https://israelpharm.com/checkout/",
            "wait_for": "body",
            "checks": [
                {"selector": "form.checkout, .woocommerce-checkout, #customer_details",
                 "label": "Checkout form", "severity": "critical"},
                {"selector": (
                    "#place_order, button[name='woocommerce_checkout_place_order'], "
                    ".place-order button, #place_order_button"
                 ),
                 "label": "Place order button", "check": "enabled", "severity": "critical"},
            ],
        },
        {
            "name": "Cart add/remove",
            # Loads a product page and clicks add-to-cart, then checks for cart confirmation.
            # Rotate through known product pages weekly; update slugs as needed.
            "url_rotation": [
                "https://israelpharm.com/product-category/vitamins/",
                "https://israelpharm.com/product-category/beauty/",
                "https://israelpharm.com/product-category/supplements/",
            ],
            "wait_for": "body",
            "checks": [
                {"selector": "li.product a.add_to_cart_button, .add_to_cart_button",
                 "label": "Add to cart button (listing)", "check": "enabled", "severity": "critical"},
            ],
            "actions": [
                {
                    "type": "click",
                    "selector": "li.product a.add_to_cart_button, .add_to_cart_button",
                    "label": "Add to cart",
                    "severity": "critical",
                    "wait_ms": 3000,
                    "assert": {
                        "selector": (
                            ".woocommerce-message, .added_to_cart, "
                            ".cart-count, .woocommerce-cart-link__count, "
                            ".mini-cart-count, span.count"
                        ),
                        "check": "visible",
                        "label": "Cart updated confirmation",
                        "severity": "critical",
                    },
                },
            ],
        },
    ],

    # ── rxfor.me ─────────────────────────────────────────────────────────────
    "https://www.rxfor.me": [
        {
            "name": "Home page",
            "url": "https://www.rxfor.me/",
            "wait_for": "body",
            "checks": [
                {"selector": "header, nav, .navbar, .header",
                 "label": "Header / navigation", "severity": "critical"},
                {"selector": (
                    "a[href*='/auth'], a[href*='consult'], a[href*='start'], "
                    "button[class*='cta'], .cta-button, a[href*='treatment']"
                 ),
                 "label": "Start consultation CTA", "severity": "critical"},
                {"selector": "main, #main, .main-content, article",
                 "label": "Main content area", "severity": "high"},
            ],
        },
        {
            "name": "Treatments listing",
            "url": "https://www.rxfor.me/treatments/",
            "wait_for": "main, body",
            "checks": [
                {"selector": (
                    ".treatment-card, .treatment-item, "
                    "a[href*='/treatments/'], article, .card"
                 ),
                 "label": "Treatment cards", "severity": "critical"},
                {"selector": "h1, h2",
                 "label": "Page heading", "severity": "high"},
            ],
        },
        {
            # Rotate through treatment pages weekly to catch individual page regressions
            "name": "Treatment page (weekly rotation)",
            "url_rotation": [
                "https://www.rxfor.me/treatments/weight-loss",
                "https://www.rxfor.me/treatments/ed-treatment",
                "https://www.rxfor.me/treatments/testosterone-men",
                "https://www.rxfor.me/treatments/testosterone-women",
                "https://www.rxfor.me/treatments/hair-loss",
                "https://www.rxfor.me/treatments/prescription-renewal",
            ],
            "wait_for": "main, body",
            "checks": [
                {"selector": "h1",
                 "label": "Treatment title", "severity": "high"},
                {"selector": (
                    "a[href*='/auth'], button[class*='start'], "
                    "a[class*='cta'], button[class*='cta'], .start-consultation"
                 ),
                 "label": "Start consultation button", "check": "enabled", "severity": "critical"},
                {"selector": "img, .hero-image, .treatment-image",
                 "label": "Treatment image", "severity": "high"},
            ],
        },
        {
            "name": "Consult / auth entry form",
            "url": "https://www.rxfor.me/auth",
            "wait_for": "form, input, body",
            "checks": [
                {"selector": "form, .form-container",
                 "label": "Consultation form", "severity": "critical"},
                {"selector": "input[type='email'], input[name*='email'], input[placeholder*='email' i]",
                 "label": "Email input field", "check": "enabled", "severity": "critical"},
                {"selector": (
                    "button[type='submit'], input[type='submit'], "
                    "button[class*='submit'], button[class*='continue'], button[class*='next']"
                 ),
                 "label": "Form submit / continue button", "check": "enabled", "severity": "critical"},
            ],
            # Fill a test email to verify the field is interactive; do NOT submit
            "actions": [
                {
                    "type": "fill",
                    "selector": "input[type='email'], input[name*='email']",
                    "label": "Email field",
                    "value": "test@example.com",
                    "severity": "critical",
                    "wait_ms": 500,
                },
            ],
        },
        {
            "name": "About page",
            "url": "https://www.rxfor.me/about",
            "wait_for": "body",
            "checks": [
                {"selector": "h1, .page-title",
                 "label": "Page title heading", "severity": "high"},
                {"selector": "main, #main, article, .content",
                 "label": "Main content", "severity": "high"},
            ],
        },
        {
            "name": "Contact page",
            "url": "https://www.rxfor.me/contact",
            "wait_for": "body",
            "checks": [
                {"selector": "h1, .page-title",
                 "label": "Page title heading", "severity": "high"},
                {"selector": "form, .contact-form, input[type='email']",
                 "label": "Contact form or email input", "severity": "high"},
            ],
        },
    ],

    # ── Reekooz ───────────────────────────────────────────────────────────────
    "https://www.reekooz.com": [
        {
            "name": "Home page",
            "url": "https://www.reekooz.com/",
            "wait_for": "body",
            "checks": [
                {"selector": "header, .site-header, #masthead",
                 "label": "Page header", "severity": "high"},
                {"selector": "nav, .nav-menu, .main-navigation, #site-navigation",
                 "label": "Main navigation", "severity": "critical"},
                {"selector": ".logo img, .site-logo, .custom-logo, header img",
                 "label": "Header logo", "severity": "high"},
                {"selector": (
                    "a[href*='shop'], a[href*='product'], "
                    ".wp-block-button__link, .btn, button"
                 ),
                 "label": "Shop / CTA button", "severity": "high"},
            ],
        },
        {
            "name": "Shop listing",
            "url": "https://www.reekooz.com/shop/",
            "wait_for": "ul.products, body",
            "checks": [
                {"selector": "ul.products, .products, li.product",
                 "label": "Product grid", "severity": "critical"},
                {"selector": "a.add_to_cart_button, .product .button",
                 "label": "Add to cart buttons in listing", "check": "enabled", "severity": "high"},
            ],
        },
        {
            "name": "Zoomind product page",
            "url": "https://www.reekooz.com/product/zoomind/",
            "wait_for": ".product, body",
            "checks": [
                {"selector": "h1.product_title, .product_title",
                 "label": "Product title", "severity": "critical"},
                {"selector": ".price, .woocommerce-Price-amount",
                 "label": "Product price", "severity": "critical"},
                {"selector": "button.single_add_to_cart_button",
                 "label": "Add to cart button", "check": "enabled", "severity": "critical"},
                {"selector": ".woocommerce-product-gallery img, .product img",
                 "label": "Product image", "severity": "high"},
            ],
            "actions": [
                {
                    "type": "click",
                    "selector": "button.single_add_to_cart_button",
                    "label": "Add to cart",
                    "severity": "critical",
                    "wait_ms": 3000,
                    "assert": {
                        "selector": (
                            ".woocommerce-message, .added_to_cart, "
                            ".cart-count, .mini-cart-count, span.count, "
                            ".woocommerce-cart-link__count"
                        ),
                        "check": "visible",
                        "label": "Cart confirmation / count update",
                        "severity": "critical",
                    },
                },
            ],
        },
        {
            "name": "NOWONDER product page",
            "url": "https://www.reekooz.com/product/nowonder-nasal-cleanser/",
            "wait_for": ".product, body",
            "checks": [
                {"selector": "h1.product_title, .product_title",
                 "label": "Product title", "severity": "critical"},
                {"selector": ".price, .woocommerce-Price-amount",
                 "label": "Product price", "severity": "critical"},
                {"selector": "button.single_add_to_cart_button",
                 "label": "Add to cart button", "check": "enabled", "severity": "critical"},
            ],
        },
        {
            # Rotate through vitamin pack pages weekly
            "name": "Vitamin pack page (weekly rotation)",
            "url_rotation": [
                "https://www.reekooz.com/product/immune-pack/",
                "https://www.reekooz.com/product/allergy-pack/",
                "https://www.reekooz.com/product/healthy-weight-pack/",
                "https://www.reekooz.com/product/sleep-pack/",
                "https://www.reekooz.com/product/stress-pack/",
                "https://www.reekooz.com/product/energy-pack/",
                "https://www.reekooz.com/product/his-essentials/",
                "https://www.reekooz.com/product/her-essentials/",
            ],
            "wait_for": ".product, body",
            "checks": [
                {"selector": "h1.product_title, .product_title",
                 "label": "Product title", "severity": "critical"},
                {"selector": ".price, .woocommerce-Price-amount",
                 "label": "Product price", "severity": "critical"},
                {"selector": "button.single_add_to_cart_button",
                 "label": "Add to cart button", "check": "enabled", "severity": "critical"},
                {"selector": ".woocommerce-product-gallery img, .product img",
                 "label": "Product image", "severity": "high"},
            ],
        },
        {
            "name": "Cart page",
            "url": "https://www.reekooz.com/cart/",
            "wait_for": "body",
            "checks": [
                {"selector": (
                    ".woocommerce-cart-form, .cart, "
                    "table.shop_table, .woocommerce-cart"
                 ),
                 "label": "Cart container", "severity": "critical"},
            ],
        },
        {
            "name": "Checkout form presence",
            "url": "https://www.reekooz.com/checkout/",
            "wait_for": "body",
            "checks": [
                {"selector": "form.checkout, .woocommerce-checkout, #customer_details",
                 "label": "Checkout form", "severity": "critical"},
                {"selector": (
                    "#place_order, button[name='woocommerce_checkout_place_order'], "
                    ".place-order button"
                 ),
                 "label": "Place order button", "check": "enabled", "severity": "critical"},
            ],
        },
    ],
}

MAX_PAGES_PER_SITE      = 200
REQUEST_DELAY           = 0.3
TIMEOUT                 = 15
EXTERNAL_CHECK_WORKERS  = 10
RETRY_ON_ERROR          = 1

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "#", "data:", "sms:", "whatsapp:")

SKIP_PATH_SEGMENTS = (
    "cdn-cgi", "wp-json", "wp-admin", "xmlrpc.php", "feed",
    ".xml", ".pdf", ".zip", ".jpg", ".jpeg", ".png", ".gif",
    ".svg", ".mp4", ".mp3", ".webp", ".ico", ".woff", ".woff2", ".ttf",
)

# Domains that block crawlers but are fine for real users — skip entirely
BOT_PROTECTED_DOMAINS = {
    "trustpilot.com", "facebook.com", "fb.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "youtube.com",
    "google.com", "google.co.il", "apple.com", "amazon.com",
    "whatsapp.com", "tiktok.com", "pinterest.com", "yelp.com",
    "tripadvisor.com", "glassdoor.com", "capterra.com",
    "g2.com", "trustindex.io", "reviews.io",
}

# Only these HTTP statuses mean "genuinely broken"
BROKEN_STATUSES = {404, 410, 500, 502, 503, 504}

CTA_KEYWORDS = {
    "buy", "order", "purchase", "add to cart", "checkout", "contact",
    "get started", "sign up", "subscribe", "book", "reserve", "request",
    "apply", "register", "download", "get quote", "try", "start",
}

# Anchors that look like JS hooks — not real missing sections
_JS_ANCHOR_RE = re.compile(r'^[!_\-0-9]|^top$|^wrap$|^content$', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize(url: str) -> str:
    url, _ = urldefrag(url)
    return url.rstrip("/")


def same_domain(url: str, base: str) -> bool:
    def root(u):
        return urlparse(u).netloc.lower().removeprefix("www.")
    return root(url) == root(base)


def crawlable(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def should_skip(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(seg in path for seg in SKIP_PATH_SEGMENTS)


def is_bot_protected(url: str) -> bool:
    netloc = urlparse(url).netloc.lower().removeprefix("www.")
    return any(netloc == d or netloc.endswith("." + d) for d in BOT_PROTECTED_DOMAINS)


def is_widget_text(text: str) -> bool:
    """Return True if the link text looks like auto-generated widget content."""
    clean = re.sub(r"[^a-zA-Z\s]", "", text).strip()
    return len(clean) < 3


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_css_selector(tag) -> str:
    """
    Generate a CSS selector for a BeautifulSoup tag.
    Usable directly in Chrome DevTools: Elements > Ctrl+F, or Console > document.querySelector(...)
    """
    if tag is None:
        return ""
    parts = []
    current = tag
    for _ in range(6):
        if not hasattr(current, "name") or not current.name or current.name == "[document]":
            break
        el_id = (current.get("id") or "").strip()
        if el_id:
            # ID is unique — stop here
            safe_id = el_id.replace('"', '\\"')
            parts.insert(0, f'#{safe_id}')
            break
        node_sel = current.name
        classes = [
            c for c in (current.get("class") or [])
            if c and not c.startswith("js-") and not c.startswith("is-") and len(c) > 1
        ]
        if classes:
            node_sel += "." + ".".join(classes[:2])
        parts.insert(0, node_sel)
        current = current.parent
    return " > ".join(parts) if parts else (tag.name or "")


def get_element_html(tag) -> str:
    """Return a compact snippet of the element's outerHTML for visual identification."""
    if tag is None:
        return ""
    raw = str(tag)
    # Collapse whitespace so it reads as one line
    compact = re.sub(r"\s+", " ", raw).strip()
    return compact[:400] + ("..." if len(compact) > 400 else "")


def make_fingerprint(site_domain: str, page_url: str, issue_type: str,
                     broken_url: str = "", visible_text: str = "") -> str:
    """
    Stable hash that identifies a finding across runs.
    Uses URL paths (not full URLs) so http vs https and trailing slashes don't create duplicates.
    The ingest endpoint uses this to skip findings that are already open.
    """
    page_path  = urlparse(page_url).path.rstrip("/") or "/"
    if broken_url:
        broken_key = urlparse(broken_url).path.rstrip("/") or broken_url[:80]
    else:
        broken_key = visible_text[:40].lower().strip()
    raw = "|".join([site_domain, page_path, issue_type, broken_key])
    return hashlib.md5(raw.encode()).hexdigest()


def head_check(url: str, session: requests.Session, retries: int = RETRY_ON_ERROR):
    """HEAD with GET fallback on 405. Retries once on transient errors."""
    for attempt in range(retries + 1):
        try:
            r = session.head(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 405:
                r = session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
                r.close()
            if r.status_code in (429, 503) and attempt < retries:
                time.sleep(2)
                continue
            return r.status_code, None
        except requests.exceptions.SSLError as e:
            if url.startswith("https://"):
                http_url = "http://" + url[8:]
                try:
                    r2 = session.head(http_url, timeout=TIMEOUT, allow_redirects=True)
                    if r2.status_code < 400:
                        return r2.status_code, None
                except Exception:
                    pass
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


def is_truly_broken(status, error: str, is_external: bool = False) -> bool:
    """
    Return True only for genuine breakage.
    For external links, network errors (timeout, connection refused) are NOT flagged —
    external sites often block crawlers transiently. Only definitive HTTP errors count.
    """
    if is_external:
        return status in BROKEN_STATUSES
    if error:
        return True   # internal connection error, SSL, timeout = real problem
    return status in BROKEN_STATUSES


# ---------------------------------------------------------------------------
# Sitemap discovery
# ---------------------------------------------------------------------------

SITEMAP_PATHS = [
    "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
    "/wp-sitemap.xml", "/page-sitemap.xml", "/post-sitemap.xml",
]


def fetch_sitemap_urls(base_url: str, session: requests.Session) -> list:
    found = []
    for path in SITEMAP_PATHS:
        try:
            r = session.get(base_url.rstrip("/") + path, timeout=10, allow_redirects=True)
            if r.status_code != 200 or "xml" not in r.headers.get("content-type", ""):
                continue
            soup = BeautifulSoup(r.text, "xml")
            for sitemap_tag in soup.find_all("sitemap"):
                loc = sitemap_tag.find("loc")
                if loc:
                    found.extend(fetch_sitemap_urls(loc.text.strip(), session))
            for url_tag in soup.find_all("url"):
                loc = url_tag.find("loc")
                if loc:
                    u = loc.text.strip()
                    if same_domain(u, base_url):
                        found.append(u)
            if found:
                print(f"    Sitemap: {len(found)} URLs at {path}")
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
        if name == "header":    return "Header"
        if name == "nav":       return "Navigation"
        if name == "footer":    return "Footer"
        if name == "form":      return "Form"
        if name == "aside":     return "Sidebar"
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
        if "ssl" in err:      return "ssl_error"
        if "timeout" in err:  return "timeout"
        return "unreachable"
    if status == 404:         return "broken_link"
    if status and status >= 500: return "server_error"
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
    elem      = element_type.lower()
    text_part = f'"{visible_text}"' if visible_text and visible_text != "[no text]" else f"A {elem}"
    page_part = f'the "{page_title}" page' if page_title else "a page"
    problems  = {
        "broken_link":       "links to a page that no longer exists",
        "broken_form":       "submits to an endpoint that isn't responding — the form won't work",
        "server_error":      f"is hitting a server error ({http_status}) — something broke on the backend",
        "ssl_error":         "has a security certificate issue — browsers may block it",
        "timeout":           "didn't respond in time — the destination may be down",
        "unreachable":       "points to a site that can't be reached",
        "empty_destination": "has no destination — it does nothing when clicked",
    }
    problem = problems.get(issue_type, f"is broken (HTTP {http_status or 'error'})")
    return f"The {text_part} {elem} on {page_part} {problem}."


# ---------------------------------------------------------------------------
# UX checks (pure HTML — no external requests)
# ---------------------------------------------------------------------------

def check_broken_images(soup, url: str, page_title: str, site_domain: str,
                        session, checked, checked_lock) -> list:
    """Internal images that return 4xx/5xx."""
    findings = []
    seen = set()
    for img in soup.find_all("img", src=True):
        src = img.get("src", "").strip()
        if not src or src.startswith("data:"):
            continue
        full_src = urljoin(url, src)
        if not same_domain(full_src, url) or should_skip(full_src):
            continue
        norm_src = normalize(full_src)
        if norm_src in seen:
            continue
        seen.add(norm_src)

        with checked_lock:
            cached = checked.get(norm_src)
        if cached is None:
            status, error = head_check(full_src, session)
            with checked_lock:
                checked[norm_src] = (status, error)
        else:
            status, error = cached

        if status in BROKEN_STATUSES:
            alt     = img.get("alt", "").strip() or "[no alt text]"
            section = get_section_hint(img)
            css_sel = get_css_selector(img)
            findings.append({
                "severity":      "high",
                "issue_type":    "broken_image",
                "fingerprint":   make_fingerprint(site_domain, url, "broken_image", full_src),
                "page_url":      url,
                "page_title":    page_title,
                "section_hint":  section,
                "element_type":  "Image",
                "visible_text":  alt[:80],
                "broken_url":    full_src,
                "http_status":   status,
                "css_selector":  css_sel,
                "element_html":  get_element_html(img),
                "devtools_cmd":  f'document.querySelector("{css_sel}")',
                "plain_english": (
                    f'An image ("{alt}") on the "{page_title}" page '
                    f"is broken and won't display — visitors will see a broken image icon."
                ),
            })
    return findings


def check_empty_elements(soup, url: str, page_title: str, site_domain: str) -> list:
    """
    Buttons and links with no accessible label.
    SVG-only icon buttons are valid (the SVG is the visual label) — skip them.
    aria-hidden elements are intentionally invisible — skip them.
    """
    findings = []

    for btn in soup.find_all("button"):
        if btn.get("aria-hidden") == "true":
            continue
        text  = btn.get_text(strip=True)
        aria  = btn.get("aria-label", "").strip()
        title = btn.get("title", "").strip()
        has_svg = bool(btn.find("svg"))
        has_img = bool(btn.find("img"))
        if not text and not aria and not title and not has_svg and not has_img:
            section = get_section_hint(btn)
            css_sel = get_css_selector(btn)
            findings.append({
                "severity":      "medium",
                "issue_type":    "empty_element",
                "fingerprint":   make_fingerprint(site_domain, url, "empty_element", "", "button:" + css_sel),
                "page_url":      url,
                "page_title":    page_title,
                "section_hint":  section,
                "element_type":  "Button",
                "visible_text":  "[no text]",
                "css_selector":  css_sel,
                "element_html":  get_element_html(btn),
                "devtools_cmd":  f'document.querySelector("{css_sel}")',
                "plain_english": (
                    f'A button on the "{page_title}" page has no visible text, label, or icon — '
                    f"users can't tell what it does."
                ),
            })

    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()
        if any(href.startswith(s) for s in SKIP_SCHEMES):
            continue
        if a.get("aria-hidden") == "true":
            continue
        text    = a.get_text(strip=True)
        aria    = a.get("aria-label", "").strip()
        has_svg = bool(a.find("svg"))
        has_img = bool(a.find("img"))
        if not text and not aria and not has_svg and not has_img:
            section = get_section_hint(a)
            css_sel = get_css_selector(a)
            findings.append({
                "severity":      "low",
                "issue_type":    "empty_element",
                "fingerprint":   make_fingerprint(site_domain, url, "empty_element", "", "link:" + css_sel),
                "page_url":      url,
                "page_title":    page_title,
                "section_hint":  section,
                "element_type":  "Link",
                "visible_text":  "[no text]",
                "css_selector":  css_sel,
                "element_html":  get_element_html(a),
                "devtools_cmd":  f'document.querySelector("{css_sel}")',
                "plain_english": (
                    f'A link on the "{page_title}" page has no visible text or icon — '
                    f"users can't see it or know where it goes."
                ),
            })

    return findings


def check_missing_title(soup, url: str, site_domain: str) -> list:
    """Pages with no <title> tag or an empty one."""
    title_tag = soup.find("title")
    if not title_tag or not title_tag.get_text(strip=True):
        return [{
            "severity":      "medium",
            "issue_type":    "missing_title",
            "fingerprint":   make_fingerprint(site_domain, url, "missing_title"),
            "page_url":      url,
            "page_title":    url,
            "section_hint":  "Page head",
            "element_type":  "Page",
            "visible_text":  "Missing title",
            "css_selector":  "head > title",
            "element_html":  "<title></title>",
            "devtools_cmd":  'document.querySelector("head > title")',
            "plain_english": (
                f"The page at {url} has no title tag — "
                f"this affects browser tabs, bookmarks, and search engine rankings."
            ),
        }]
    return []


def check_mixed_content(soup, url: str, page_title: str, site_domain: str) -> list:
    """HTTP resources loaded on an HTTPS page — browsers block these silently."""
    if not url.startswith("https://"):
        return []

    findings = []
    checks = [
        (soup.find_all("img",    src=True),         "src",  "Image",      "high"),
        (soup.find_all("script", src=True),         "src",  "Script",     "high"),
        (soup.find_all("iframe", src=True),         "src",  "iFrame",     "medium"),
        (soup.find_all("link",   rel="stylesheet"), "href", "Stylesheet", "medium"),
    ]
    seen = set()
    for tags, attr, elem_label, severity in checks:
        for tag in tags:
            resource = tag.get(attr, "").strip()
            if resource.startswith("http://") and resource not in seen:
                seen.add(resource)
                section = get_section_hint(tag)
                css_sel = get_css_selector(tag)
                findings.append({
                    "severity":      severity,
                    "issue_type":    "mixed_content",
                    "fingerprint":   make_fingerprint(site_domain, url, "mixed_content", resource),
                    "page_url":      url,
                    "page_title":    page_title,
                    "section_hint":  section,
                    "element_type":  elem_label,
                    "visible_text":  resource[:80],
                    "broken_url":    resource,
                    "css_selector":  css_sel,
                    "element_html":  get_element_html(tag),
                    "devtools_cmd":  f'document.querySelector("{css_sel}")',
                    "plain_english": (
                        f'A {elem_label.lower()} on "{page_title}" loads over HTTP on an HTTPS page '
                        f"— browsers will block it silently, breaking the page for visitors."
                    ),
                })
    return findings


def check_broken_anchors(soup, url: str, page_title: str, site_domain: str) -> list:
    """
    <a href="#id"> links where the target ID doesn't exist on the page.
    Skips JS-hook anchors (#!, #0, #top, etc.) which are intentionally used by scripts.
    """
    all_ids     = {tag.get("id")   for tag in soup.find_all(id=True)}
    all_names   = {tag.get("name") for tag in soup.find_all(attrs={"name": True})}
    valid_anchors = all_ids | all_names

    findings = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href.startswith("#"):
            continue
        anchor = href[1:]
        if not anchor:
            continue
        # Skip anchors that are clearly JS hooks, not real section targets
        if _JS_ANCHOR_RE.match(anchor):
            continue
        if anchor not in valid_anchors:
            visible = tag.get_text(strip=True) or tag.get("aria-label", "") or "[no text]"
            section = get_section_hint(tag)
            css_sel = get_css_selector(tag)
            findings.append({
                "severity":      "low",
                "issue_type":    "broken_anchor",
                "fingerprint":   make_fingerprint(site_domain, url, "broken_anchor", f"#{anchor}"),
                "page_url":      url,
                "page_title":    page_title,
                "section_hint":  section,
                "element_type":  "Anchor link",
                "visible_text":  visible[:80],
                "broken_url":    f"{url}#{anchor}",
                "css_selector":  css_sel,
                "element_html":  get_element_html(tag),
                "devtools_cmd":  f'document.querySelector("{css_sel}")',
                "plain_english": (
                    f'The "{visible}" link on "{page_title}" jumps to #{anchor} '
                    f"but that section doesn't exist on the page — clicking it does nothing."
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# Priority test helpers
# ---------------------------------------------------------------------------

def _priority_finding(
    site_domain: str,
    url: str,
    page_title: str,
    test_name: str,
    issue_type: str,
    severity: str,
    visible_text: str,
    plain_english: str,
    http_status=None,
    selector: str = "",
    element_html: str = "",
) -> dict:
    """Build a finding dict in the same format as the crawler, for priority test failures."""
    fp_key = selector or visible_text[:40]
    return {
        "severity":      severity,
        "issue_type":    issue_type,
        "fingerprint":   make_fingerprint(site_domain, url, issue_type, fp_key),
        "page_url":      url,
        "page_title":    page_title,
        "section_hint":  test_name,
        "element_type":  "Priority check",
        "visible_text":  visible_text[:80],
        "broken_url":    "",
        "http_status":   http_status,
        "css_selector":  selector,
        "element_html":  element_html[:400] if element_html else "",
        "devtools_cmd":  f'document.querySelector("{selector}")' if selector else "",
        "plain_english": plain_english,
    }


def _run_element_check(
    page,
    site_domain: str,
    url: str,
    page_title: str,
    test_name: str,
    selector: str,
    label: str,
    severity: str,
    check_type: str,
):
    """
    Run a single element check on an open Playwright page.
    Returns a finding dict if the check fails, or None if it passes.
    check_type: "visible" (default) | "enabled" (implies visible too)
    """
    try:
        count = page.locator(selector).count()
        if count == 0:
            return _priority_finding(
                site_domain, url, page_title, test_name,
                "missing_element", severity,
                f"{label} not found",
                (
                    f'The "{label}" element was not found on the {test_name} page '
                    f"(selector: {selector}). It may have been removed or the page structure changed."
                ),
                selector=selector,
            )

        locator = page.locator(selector).first

        if check_type in ("visible", "enabled"):
            visible = locator.is_visible()
            if not visible:
                try:
                    elem_html = locator.evaluate("el => el.outerHTML")
                except Exception:
                    elem_html = ""
                return _priority_finding(
                    site_domain, url, page_title, test_name,
                    "hidden_element", severity,
                    f"{label} is hidden",
                    (
                        f'The "{label}" element on the {test_name} page is present in the HTML '
                        f"but hidden via CSS (display:none / visibility:hidden). Visitors cannot see it."
                    ),
                    selector=selector,
                    element_html=elem_html,
                )

        if check_type == "enabled":
            enabled = locator.is_enabled()
            if not enabled:
                return _priority_finding(
                    site_domain, url, page_title, test_name,
                    "button_disabled", severity,
                    f"{label} is disabled",
                    (
                        f'The "{label}" button on the {test_name} page is visible but has the '
                        f"disabled attribute set — users cannot click it."
                    ),
                    selector=selector,
                )

    except Exception as e:
        return _priority_finding(
            site_domain, url, page_title, test_name,
            "missing_element", severity,
            f"{label} check error",
            (
                f'Checking the "{label}" element on the {test_name} page raised an error: '
                f"{str(e)[:120]}"
            ),
            selector=selector,
        )

    return None  # check passed


def _run_action_step(page, site_domain: str, url: str, page_title: str, test_name: str, step: dict):
    """
    Execute one interaction step (click or fill) on an open Playwright page.
    Returns a finding dict if the step or its post-action assertion fails, or None on success.
    """
    action_type = step["type"]
    selector    = step["selector"]
    label       = step.get("label", selector)
    severity    = step.get("severity", "critical")

    try:
        locator = page.locator(selector).first

        if action_type == "click":
            if not locator.is_visible():
                return _priority_finding(
                    site_domain, url, page_title, test_name,
                    "hidden_element", severity,
                    f"{label} not clickable (hidden)",
                    (
                        f'The "{label}" element on the {test_name} page is hidden '
                        f"— the click action could not be performed."
                    ),
                    selector=selector,
                )
            locator.click(timeout=5000)
            page.wait_for_timeout(step.get("wait_ms", 3000))

        elif action_type == "fill":
            locator.fill(step.get("value", ""), timeout=5000)
            page.wait_for_timeout(step.get("wait_ms", 500))

        # Post-action assertion
        assert_spec = step.get("assert")
        if assert_spec:
            assert_sel      = assert_spec["selector"]
            assert_check    = assert_spec.get("check", "visible")
            assert_label    = assert_spec.get("label", assert_sel)
            assert_severity = assert_spec.get("severity", severity)

            if assert_check == "visible":
                try:
                    page.wait_for_selector(assert_sel, timeout=5000, state="visible")
                except Exception:
                    exists = page.locator(assert_sel).count() > 0
                    issue_type = "hidden_element" if exists else "missing_element"
                    return _priority_finding(
                        site_domain, url, page_title, test_name,
                        issue_type, assert_severity,
                        f"After '{label}': {assert_label} not visible",
                        (
                            f'After clicking "{label}" on the {test_name} page, '
                            f'the expected "{assert_label}" did not appear — '
                            f"the action may have failed silently."
                        ),
                        selector=assert_sel,
                    )

            elif assert_check == "url_contains":
                expected = assert_spec.get("value", "")
                current  = page.url
                if expected not in current:
                    return _priority_finding(
                        site_domain, url, page_title, test_name,
                        "interaction_failed", assert_severity,
                        f"After '{label}': unexpected URL",
                        (
                            f'After clicking "{label}" on the {test_name} page, '
                            f'expected the URL to contain "{expected}" '
                            f'but landed on: {current[:80]}'
                        ),
                        selector=selector,
                    )

    except Exception as e:
        return _priority_finding(
            site_domain, url, page_title, test_name,
            "interaction_failed", severity,
            f"'{label}' action failed",
            f'The "{label}" interaction on the {test_name} page failed: {str(e)[:120]}',
            selector=selector,
        )

    return None  # step passed


# ---------------------------------------------------------------------------
# Priority page checker (Playwright-based)
# ---------------------------------------------------------------------------

def check_priority_pages(base_url: str, secret: str = "") -> dict:
    """
    Run the PRIORITY_TESTS for a single site using a headless Playwright browser.
    Checks computed CSS visibility, element presence, button enabled state, and
    optional click/fill interactions.  Returns a result dict in the same format
    as crawl_site() so it can be passed directly to post_to_ingest().
    """
    if not PLAYWRIGHT_AVAILABLE:
        print(f"  [priority] Playwright not available — skipping {base_url}")
        return {
            "site":          urlparse(base_url).netloc,
            "pages_crawled": 0,
            "started_at":    now_iso(),
            "completed_at":  now_iso(),
            "findings":      [],
        }

    site_domain   = urlparse(base_url).netloc.lower().removeprefix("www.")
    tests         = PRIORITY_TESTS.get(base_url, [])
    findings: list = []
    pages_checked = 0
    started_at    = now_iso()

    print(f"\n{'='*65}")
    print(f"  Priority tests: {base_url}  ({len(tests)} tests)")
    print(f"{'='*65}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=HEADERS["User-Agent"],
        )

        for test in tests:
            test_name = test["name"]

            # Resolve URL: fixed or weekly rotation
            if "url" in test:
                url = test["url"]
            else:
                rotation = test["url_rotation"]
                url = rotation[_WEEK_NUM % len(rotation)]

            print(f"  [{pages_checked + 1:>2}] {test_name}: {url[:70]}")

            findings_before = len(findings)
            page       = context.new_page()
            page_title = test_name  # fallback until real title is fetched

            try:
                resp        = page.goto(url, wait_until="domcontentloaded", timeout=20_000)
                http_status = resp.status if resp else None

                if http_status and http_status >= 400:
                    findings.append(_priority_finding(
                        site_domain, url, page_title, test_name,
                        "page_load_failed", "critical",
                        f"Page load failed (HTTP {http_status})",
                        (
                            f"The {test_name} page at {url} returned HTTP {http_status} "
                            f"and cannot be accessed — it may be offline or access-restricted."
                        ),
                        http_status=http_status,
                    ))
                    pages_checked += 1
                    page.close()
                    continue

                # Wait for key element before running checks
                wait_sel = test.get("wait_for")
                if wait_sel:
                    try:
                        page.wait_for_selector(wait_sel, timeout=6000)
                    except Exception:
                        pass  # keep going — checks will catch missing elements

                # Fetch actual page title
                try:
                    page_title = page.title() or test_name
                except Exception:
                    pass

                # Run element checks
                for chk in test.get("checks", []):
                    finding = _run_element_check(
                        page, site_domain, url, page_title, test_name,
                        chk["selector"],
                        chk["label"],
                        chk.get("severity", "high"),
                        chk.get("check", "visible"),
                    )
                    if finding:
                        findings.append(finding)

                # Run interaction steps
                for step in test.get("actions", []):
                    finding = _run_action_step(
                        page, site_domain, url, page_title, test_name, step
                    )
                    if finding:
                        findings.append(finding)

                pages_checked += 1

            except Exception as e:
                print(f"       Error loading {url}: {e}")
                findings.append(_priority_finding(
                    site_domain, url, page_title, test_name,
                    "page_load_failed", "critical",
                    "Page failed to load",
                    f"The {test_name} page at {url} could not be loaded: {str(e)[:120]}",
                ))
                pages_checked += 1

            # Screenshot if the test produced any findings
            new_findings = findings[findings_before:]
            if new_findings:
                try:
                    img_bytes = page.screenshot(type="jpeg", quality=75, full_page=False)
                    img_b64   = base64.b64encode(img_bytes).decode("utf-8")
                    shot_url  = upload_screenshot(url, img_b64, secret)
                    if shot_url:
                        for f in new_findings:
                            f["screenshot_url"] = shot_url
                except Exception as e:
                    print(f"       Screenshot failed: {e}")

            page.close()

        browser.close()

    completed_at = now_iso()
    print(f"  Done.  Tests run: {pages_checked}  |  Findings: {len(findings)}")

    return {
        "site":          urlparse(base_url).netloc,
        "pages_crawled": pages_checked,
        "started_at":    started_at,
        "completed_at":  completed_at,
        "findings":      findings,
    }


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

def crawl_site(base_url: str, secret: str = "") -> dict:
    session = requests.Session()
    session.headers.update(HEADERS)

    site_domain  = urlparse(base_url).netloc.lower().removeprefix("www.")
    visited      = set()
    queue        = deque()
    checked      = {}
    checked_lock = Lock()
    findings     = []
    pages_crawled = 0
    started_at   = now_iso()

    print(f"\n{'='*65}")
    print(f"  Crawling: {base_url}")
    print(f"{'='*65}")

    # Seed priority pages first, then sitemap, then let crawler discover the rest
    for u in PRIORITY_URLS.get(base_url, []):
        queue.append(u)
    sitemap_urls = fetch_sitemap_urls(base_url, session)
    for u in sitemap_urls:
        queue.append(u)
    if not queue:
        queue.appendleft(base_url)

    def check_url(url: str):
        norm = normalize(url)
        with checked_lock:
            if norm in checked:
                return checked[norm]
        result = head_check(url, session)
        with checked_lock:
            checked[norm] = result
        return result

    while queue and pages_crawled < MAX_PAGES_PER_SITE:
        url  = queue.popleft()
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

        with checked_lock:
            checked[norm] = (resp.status_code, None)

        if "text/html" not in resp.headers.get("content-type", ""):
            time.sleep(REQUEST_DELAY)
            continue

        soup       = BeautifulSoup(resp.text, "html.parser")
        title_tag  = soup.find("title")
        page_title = title_tag.get_text(strip=True)[:120] if title_tag else urlparse(url).path or base_url

        page_findings_before = len(findings)

        # --- External link checks ---
        external_items = {}
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
            else:
                if not is_bot_protected(full):
                    external_items[norm_full] = (full, tag)

        def check_and_return(item):
            full, tag = item
            status, error = check_url(full)
            return full, tag, status, error

        with ThreadPoolExecutor(max_workers=EXTERNAL_CHECK_WORKERS) as pool:
            futures = {pool.submit(check_and_return, item): item
                       for item in external_items.values()}
            for future in as_completed(futures):
                full, tag, status, error = future.result()
                # External links: only flag definitive HTTP errors, not transient network issues
                if not is_truly_broken(status, error, is_external=True):
                    continue
                visible    = (tag.get_text(strip=True) or tag.get("aria-label", "") or "[no text]")[:80]
                if is_widget_text(visible):
                    continue
                section    = get_section_hint(tag)
                elem_type  = get_element_type(tag, section, visible)
                issue_type = get_issue_type(status, error or "", is_form=False)
                severity   = get_severity(elem_type, issue_type, url, full)
                css_sel    = get_css_selector(tag)
                findings.append({
                    "severity":      severity,
                    "issue_type":    issue_type,
                    "fingerprint":   make_fingerprint(site_domain, url, issue_type, full),
                    "page_url":      url,
                    "page_title":    page_title,
                    "section_hint":  section,
                    "element_type":  elem_type,
                    "visible_text":  visible,
                    "broken_url":    full,
                    "http_status":   status,
                    "css_selector":  css_sel,
                    "element_html":  get_element_html(tag),
                    "devtools_cmd":  f'document.querySelector("{css_sel}")',
                    "plain_english": get_plain_english(
                        visible, elem_type, page_title, issue_type, status, error or ""
                    ),
                })

        # --- Form action checks ---
        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip()
            if not action or any(action.startswith(s) for s in SKIP_SCHEMES):
                continue
            full_action = urljoin(url, action)
            if not crawlable(full_action) or should_skip(full_action):
                continue
            status, error = check_url(full_action)
            if not is_truly_broken(status, error):
                continue
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
            css_sel = get_css_selector(form)
            findings.append({
                "severity":      severity,
                "issue_type":    issue_type,
                "fingerprint":   make_fingerprint(site_domain, url, issue_type, full_action),
                "page_url":      url,
                "page_title":    page_title,
                "section_hint":  section,
                "element_type":  "Form submit",
                "visible_text":  visible,
                "broken_url":    full_action,
                "http_status":   status,
                "css_selector":  css_sel,
                "element_html":  get_element_html(form),
                "devtools_cmd":  f'document.querySelector("{css_sel}")',
                "plain_english": get_plain_english(
                    visible, "Form submit", page_title, issue_type, status, error or ""
                ),
            })

        # --- UX checks (pure HTML) ---
        findings.extend(check_broken_images(soup, url, page_title, site_domain, session, checked, checked_lock))
        findings.extend(check_empty_elements(soup, url, page_title, site_domain))
        findings.extend(check_missing_title(soup, url, site_domain))
        findings.extend(check_mixed_content(soup, url, page_title, site_domain))
        findings.extend(check_broken_anchors(soup, url, page_title, site_domain))

        # --- Screenshot for pages with new findings ---
        new_findings = [f for f in findings[page_findings_before:] if "screenshot_url" not in f]
        if new_findings and PLAYWRIGHT_AVAILABLE:
            print(f"       Taking screenshot of {url[:70]}")
            img_b64 = take_screenshot(url)
            if img_b64:
                shot_url = upload_screenshot(url, img_b64, secret)
                if shot_url:
                    for f in new_findings:
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

def take_screenshot(url: str):
    if not PLAYWRIGHT_AVAILABLE:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page    = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(url, wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(1500)
            img_bytes = page.screenshot(type="jpeg", quality=75, full_page=False)
            browser.close()
        return base64.b64encode(img_bytes).decode("utf-8")
    except Exception as e:
        print(f"    Screenshot failed for {url}: {e}")
        return None


def upload_screenshot(page_url: str, image_base64: str, secret: str):
    upload_url = INGEST_URL.replace("/crawler/ingest", "/crawler/upload-screenshot")
    try:
        resp = requests.post(
            upload_url,
            json={"page_url": page_url, "image_base64": image_base64, "mime_type": "image/jpeg"},
            headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json().get("screenshot_url")
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
            headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            print(f"  OK scan_id={data.get('scan_id')}  inserted={data.get('inserted')}  skipped={data.get('skipped_duplicates')}")
            return True
        print(f"  FAIL HTTP {resp.status_code}: {resp.text[:200]}")
        return False
    except Exception as e:
        print(f"  FAIL Request failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # ── CLI flags ─────────────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(description="SiteWatch Crawler")
    parser.add_argument(
        "--test-mode",
        choices=["priority", "crawl"],
        default=None,
        help=(
            "priority — run only Playwright-based priority transaction tests (fast, ~2 min); "
            "crawl    — full HTML crawl (default when flag is omitted)"
        ),
    )
    args = parser.parse_args()

    # Also accept TEST_MODE env var so GitHub Actions workflows can set it without
    # changing the `run: python checker.py` command.
    test_mode = args.test_mode or os.environ.get("TEST_MODE", "").strip().lower() or "crawl"

    # ── Secret ────────────────────────────────────────────────────────────────
    secret = os.environ.get("CRAWLER_INGEST_SECRET", "").strip()
    if not secret:
        print("ERROR: CRAWLER_INGEST_SECRET env var is not set.")
        sys.exit(1)

    # ── Site filter (shared by both modes) ───────────────────────────────────
    site_filter = os.environ.get("SITE_FILTER", "").strip().lower().removeprefix("www.")
    if site_filter:
        sites_to_run = [
            s for s in SITES
            if site_filter in s.lower().removeprefix("https://").removeprefix("www.")
        ]
        if not sites_to_run:
            print(f"ERROR: No site matched SITE_FILTER='{site_filter}'. Available: {SITES}")
            sys.exit(1)
        print(f"SITE_FILTER='{site_filter}' — running on: {sites_to_run}")
    else:
        sites_to_run = SITES

    # ── Run ───────────────────────────────────────────────────────────────────
    if test_mode == "priority":
        # Priority mode: Playwright-based transaction tests only — one site at a time
        # (Playwright does not benefit from multi-threading; browser isolation is per call)
        print(f"\nMode: PRIORITY TESTS  (week {_WEEK_NUM})")
        results = [check_priority_pages(url, secret) for url in sites_to_run]

    else:
        # Crawl mode: full HTML crawl (original behaviour)
        print(f"\nMode: FULL CRAWL")
        from concurrent.futures import ThreadPoolExecutor as SitePool
        results = []
        with SitePool(max_workers=len(sites_to_run)) as pool:
            futures = {pool.submit(crawl_site, url, secret): url for url in sites_to_run}
            for future in as_completed(futures):
                results.append(future.result())

    # ── Post results ──────────────────────────────────────────────────────────
    success_count = 0
    for payload in results:
        if post_to_ingest(payload, secret):
            success_count += 1

    print(f"\n{'='*65}")
    print(f"  Done. {success_count}/{len(sites_to_run)} sites posted successfully.")
    print(f"{'='*65}\n")

    if success_count < len(sites_to_run):
        sys.exit(1)
