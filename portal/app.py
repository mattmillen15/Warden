#!/usr/bin/env python3
"""
Warden — Local Admin Portal
Runs on localhost for managing domain aging, categorization, email warmup, and site generation.
Optionally auto-pushes to GitHub when configured.
"""

import json
import os
import shutil
import re
import socket
import platform
import hashlib
import base64
import binascii
import subprocess
import tempfile
import time
import random
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urljoin, quote

import dns.resolver
import requests
try:
    from seleniumbase import Driver as SBDriver
except Exception:
    SBDriver = None
try:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except Exception:
    By = None
    WebDriverWait = None
    EC = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None
try:
    from apscheduler.schedulers.background import BackgroundScheduler
except Exception:
    BackgroundScheduler = None
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, flash,
    send_file, Response,
)
from domain_finder import CustomDomainFinder, DomainFinder, get_wayback_info, is_human_readable

app = Flask(__name__)
app.secret_key = os.urandom(32)

BASE_DIR = Path(__file__).resolve().parent.parent
PORTAL_DIR = Path(__file__).resolve().parent
CONFIG_FILE = PORTAL_DIR / "config.json"
DOMAINS_FILE = BASE_DIR / "domains.json"
TEMPLATES_DIR = BASE_DIR / "templates"
OUTPUT_DIR = BASE_DIR / "output"
SCAN_STATE_FILE = PORTAL_DIR / "scan_state.json"
EMAIL_LOG_FILE = PORTAL_DIR / "email_log.json"
WARDEN_KEY_FILE = PORTAL_DIR / ".warden.key"
WARDEN_ENCRYPTION_MARKER = "_warden_encrypted_v1"
WARDEN_KEYCHAIN_SERVICE = "warden.master.key"

@app.route("/favicon.ico")
def favicon():
    return send_file(PORTAL_DIR / "static" / "img" / "warden-logo.svg", mimetype="image/svg+xml")

CATEGORIZATION_PROVIDER_ORDER = [
    "trendmicro",
    "mcafee",
    "bluecoat",
    "talosintelligence",
]

MANUAL_CATEGORIZATION_PROVIDER_ORDER = [
    "trendmicro",
    "mcafee",
    "bluecoat",
    "paloalto",
    "brightcloud",
    "watchguard",
    "talosintelligence",
]

ALLOWED_DOMAIN_STATUSES = ("deployed", "aging", "active", "burned", "retired")

CATEGORIZATION_PROVIDERS = {
    "trendmicro": {
        "key": "trendmicro",
        "name": "TrendMicro",
        "portal_url": "https://global.sitesafety.trendmicro.com/",
        "check_url": "https://global.sitesafety.trendmicro.com/result.php?url={domain}",
        "submit_url": "https://global.sitesafety.trendmicro.com/",
        "category_patterns": [r"category\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
        "reputation_patterns": [r"safety\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
    },
    "mcafee": {
        "key": "mcafee",
        "name": "McAfee / Trellix",
        "portal_url": "https://sitelookup.mcafee.com/",
        "check_url": "https://sitelookup.mcafee.com/en/feedback/url?action=checksingle&url={domain}",
        "submit_url": "https://sitelookup.mcafee.com/en/feedback/url",
        "category_patterns": [r"category\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
        "reputation_patterns": [r"reputation\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
    },
    "lightspeedsystems": {
        "key": "lightspeedsystems",
        "name": "Lightspeed Systems",
        "portal_url": "https://archive.lightspeedsystems.com/",
        "check_url": "https://archive.lightspeedsystems.com/?url={domain}",
        "submit_url": None,
        "category_patterns": [r"category\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
    },
    "brightcloud": {
        "key": "brightcloud",
        "name": "BrightCloud",
        "portal_url": "https://www.brightcloud.com/tools/url-ip-lookup.php",
        "check_url": "https://www.brightcloud.com/tools/url-ip-lookup.php?url={domain}",
        "submit_url": "https://www.brightcloud.com/tools/url-ip-lookup.php",
        "category_patterns": [r"category\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
        "reputation_patterns": [r"reputation\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
    },
    "bluecoat": {
        "key": "bluecoat",
        "name": "Symantec / Bluecoat",
        "portal_url": "https://sitereview.bluecoat.com/",
        "check_url": "https://sitereview.bluecoat.com/resource/lookup",
        "check_method": "post",
        "check_payload": {"url": "{domain}"},
        "submit_url": "https://sitereview.bluecoat.com/",
        "category_patterns": [r"categorized\s+as\s+([A-Za-z0-9 /&()\-]+)"],
    },
    "paloalto": {
        "key": "paloalto",
        "name": "Palo Alto (PAN-DB)",
        "portal_url": "https://urlfiltering.paloaltonetworks.com/",
        "check_url": "https://urlfiltering.paloaltonetworks.com/",
        "submit_url": "https://urlfiltering.paloaltonetworks.com/",
        "category_patterns": [r"category\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
        "reputation_patterns": [r"risk\s*level\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
    },
    "zvelo": {
        "key": "zvelo",
        "name": "Zvelo",
        "portal_url": "https://tools.zvelo.com/",
        "check_url": "https://tools.zvelo.com/?url={domain}",
        "submit_url": "https://tools.zvelo.com/",
        "category_patterns": [r"category\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
    },
    "watchguard": {
        "key": "watchguard",
        "name": "WatchGuard",
        "portal_url": "https://securityportal.watchguard.com/UrlCategory",
        "check_url": "https://securityportal.watchguard.com/UrlCategory",
        "submit_url": "https://securityportal.watchguard.com/UrlCategory",
        "requires_auth": True,
        "category_patterns": [r"categorized\s+as\s+([A-Za-z0-9 /&()\-]+)"],
    },
    "talosintelligence": {
        "key": "talosintelligence",
        "name": "Cisco Talos",
        "portal_url": "https://talosintelligence.com/reputation_center/",
        "check_url": "https://talosintelligence.com/reputation_center/lookup?search={domain}",
        "submit_url": "https://talosintelligence.com/reputation_center/web_categorization",
        "requires_auth": True,
        "category_patterns": [r"content\s+category\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
        "reputation_patterns": [r"reputation\s*[:\-]\s*([A-Za-z0-9 /&()\-]+)"],
    },
}

MONITOR_FREQUENCIES = {
    "daily": {"hours": 24, "label": "Daily"},
    "every_3_days": {"hours": 72, "label": "Every 3 Days"},
    "weekly": {"hours": 168, "label": "Weekly"},
}

MONITOR_JOB_ID = "warden_auto_scan"
WARMUP_JOB_ID = "warden_auto_warmup"
monitor_scheduler = BackgroundScheduler(daemon=True) if BackgroundScheduler else None
WARMUP_LOG_PAGE_SIZE = 20

WARMUP_FREQUENCIES = {
    "every_12_hours": {"hours": 12, "label": "Every 12 Hours"},
    "daily": {"hours": 24, "label": "Daily"},
    "every_2_days": {"hours": 48, "label": "Every 2 Days"},
    "weekly": {"hours": 168, "label": "Weekly"},
}

MAILJET_SYNC_LOOKBACKS = {
    "1h": {"seconds": 3600, "label": "1 Hour", "limit_hint": 100},
    "12h": {"seconds": 12 * 3600, "label": "12 Hours", "limit_hint": 200},
    "1d": {"seconds": 24 * 3600, "label": "1 Day", "limit_hint": 300},
    "1w": {"seconds": 7 * 24 * 3600, "label": "1 Week", "limit_hint": 500},
    "30d": {"seconds": 30 * 24 * 3600, "label": "30 Days", "limit_hint": 500},
}
DEFAULT_MAILJET_SYNC_LOOKBACK = "1d"

EMAIL_PROVIDER_OPTIONS = {
    "mailjet": {"label": "Mailjet"},
    "smtp2go": {"label": "SMTP2GO"},
}
DEFAULT_EMAIL_PROVIDER = "mailjet"
SMTP2GO_API_BASE = "https://api.smtp2go.com/v3"

# ── Secure storage + config helpers ─────────────────────────────


def _decode_key_material(raw_value):
    raw = str(raw_value or "").strip()
    if not raw:
        return None
    try:
        padded = raw + ("=" * ((4 - len(raw) % 4) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    try:
        decoded = binascii.unhexlify(raw)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    return None


def _load_key_from_macos_keychain():
    if platform.system() != "Darwin":
        return None
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", WARDEN_KEYCHAIN_SERVICE, "-w"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        return _decode_key_material(result.stdout.strip())
    except Exception:
        return None


def _save_key_to_macos_keychain(key_bytes):
    if platform.system() != "Darwin":
        return False
    encoded = base64.urlsafe_b64encode(key_bytes).decode("utf-8")
    try:
        result = subprocess.run(
            ["security", "add-generic-password", "-U", "-s", WARDEN_KEYCHAIN_SERVICE, "-w", encoded],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _load_or_create_warden_key():
    env_key = _decode_key_material(os.environ.get("WARDEN_MASTER_KEY", ""))
    if env_key:
        return env_key

    keychain_key = _load_key_from_macos_keychain()
    if keychain_key:
        return keychain_key

    if WARDEN_KEY_FILE.exists():
        disk_key = _decode_key_material(WARDEN_KEY_FILE.read_text())
        if disk_key:
            _save_key_to_macos_keychain(disk_key)
            return disk_key

    generated = os.urandom(32)
    if _save_key_to_macos_keychain(generated):
        return generated
    try:
        WARDEN_KEY_FILE.write_text(base64.urlsafe_b64encode(generated).decode("utf-8") + "\n")
        os.chmod(WARDEN_KEY_FILE, 0o600)
    except Exception:
        pass
    return generated


def _encrypt_payload(data):
    if AESGCM is None:
        return data
    key = _load_or_create_warden_key()
    nonce = os.urandom(12)
    plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        WARDEN_ENCRYPTION_MARKER: True,
        "nonce": base64.urlsafe_b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("utf-8"),
    }


def _decrypt_payload(payload):
    if not isinstance(payload, dict):
        return None
    if not payload.get(WARDEN_ENCRYPTION_MARKER):
        return None
    if AESGCM is None:
        return None
    try:
        key = _load_or_create_warden_key()
        nonce = base64.urlsafe_b64decode(payload.get("nonce", "").encode("utf-8"))
        ciphertext = base64.urlsafe_b64decode(payload.get("ciphertext", "").encode("utf-8"))
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None


def _load_secure_json(path, default):
    if not path.exists():
        return default
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return default

    decrypted = _decrypt_payload(payload)
    if decrypted is not None:
        return decrypted

    # Encrypted payload exists but could not be decrypted (bad key/corrupt file).
    if isinstance(payload, dict) and payload.get(WARDEN_ENCRYPTION_MARKER):
        return default

    # Plaintext migration: keep app functional and re-save encrypted.
    if isinstance(payload, (dict, list)):
        try:
            _save_secure_json(path, payload)
        except Exception:
            pass
        return payload

    return default


def _save_secure_json(path, data):
    payload = _encrypt_payload(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def load_config():
    cfg = _load_secure_json(CONFIG_FILE, {})
    if not isinstance(cfg, dict):
        return {}
    return cfg


def save_config(cfg):
    _save_secure_json(CONFIG_FILE, cfg or {})


def normalize_email_provider(value):
    provider = str(value or DEFAULT_EMAIL_PROVIDER).strip().lower()
    if provider not in EMAIL_PROVIDER_OPTIONS:
        provider = DEFAULT_EMAIL_PROVIDER
    return provider


def get_email_provider(cfg=None):
    data = cfg if isinstance(cfg, dict) else load_config()
    return normalize_email_provider(data.get("email_provider"))


def get_email_provider_label(provider=None, cfg=None):
    key = normalize_email_provider(provider or get_email_provider(cfg))
    return (EMAIL_PROVIDER_OPTIONS.get(key) or {}).get("label", "Mail Provider")


def mailjet_provider_configured(cfg=None):
    data = cfg if isinstance(cfg, dict) else load_config()
    return bool(str(data.get("mailjet_api_key") or "").strip() and str(data.get("mailjet_api_secret") or "").strip())


def smtp2go_provider_configured(cfg=None):
    data = cfg if isinstance(cfg, dict) else load_config()
    return bool(str(data.get("smtp2go_api_key") or "").strip())


def current_mail_provider_configured(cfg=None):
    data = cfg if isinstance(cfg, dict) else load_config()
    provider = get_email_provider(data)
    if provider == "smtp2go":
        return smtp2go_provider_configured(data)
    return mailjet_provider_configured(data)


def load_domains():
    data = _load_secure_json(DOMAINS_FILE, {"domains": []})
    if not isinstance(data, dict):
        return {"domains": []}
    data.setdefault("domains", [])
    return data


def save_domains(data):
    payload = data if isinstance(data, dict) else {"domains": []}
    payload.setdefault("domains", [])
    _save_secure_json(DOMAINS_FILE, payload)


def default_scan_state():
    return {
        "domains": {},
        "monitor": {
            "enabled": False,
            "frequency": "weekly",
            "last_full_scan": None,
        },
    }


def load_scan_state():
    state = _load_secure_json(SCAN_STATE_FILE, default_scan_state())
    if not isinstance(state, dict):
        return default_scan_state()
    state.setdefault("domains", {})
    state.setdefault("monitor", default_scan_state()["monitor"])
    state["monitor"].setdefault("enabled", False)
    state["monitor"].setdefault("frequency", "weekly")
    state["monitor"].setdefault("last_full_scan", None)
    return state


def save_scan_state(state):
    _save_secure_json(SCAN_STATE_FILE, state or default_scan_state())


def default_email_log():
    return {
        "entries": [],
        "last_synced_at": None,
        "mailjet_sync_summary": None,
        "mailjet_sync_lookback": DEFAULT_MAILJET_SYNC_LOOKBACK,
        "mailjet_sync_label": (MAILJET_SYNC_LOOKBACKS.get(DEFAULT_MAILJET_SYNC_LOOKBACK) or {}).get("label", "1 Day"),
    }


def load_email_log():
    payload = _load_secure_json(EMAIL_LOG_FILE, default_email_log())
    if not isinstance(payload, dict):
        return default_email_log()
    payload.setdefault("entries", [])
    payload.setdefault("last_synced_at", None)
    payload.setdefault("mailjet_sync_summary", None)
    payload.setdefault("mailjet_sync_lookback", DEFAULT_MAILJET_SYNC_LOOKBACK)
    payload.setdefault("mailjet_sync_label", (MAILJET_SYNC_LOOKBACKS.get(DEFAULT_MAILJET_SYNC_LOOKBACK) or {}).get("label", "1 Day"))
    return payload


def save_email_log(payload):
    data = payload if isinstance(payload, dict) else default_email_log()
    data.setdefault("entries", [])
    data.setdefault("last_synced_at", None)
    data.setdefault("mailjet_sync_summary", None)
    data.setdefault("mailjet_sync_lookback", DEFAULT_MAILJET_SYNC_LOOKBACK)
    data.setdefault("mailjet_sync_label", (MAILJET_SYNC_LOOKBACKS.get(DEFAULT_MAILJET_SYNC_LOOKBACK) or {}).get("label", "1 Day"))
    _save_secure_json(EMAIL_LOG_FILE, data)


def parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _ensure_aware_utc(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_mailjet_sync_lookback(value):
    key = str(value or DEFAULT_MAILJET_SYNC_LOOKBACK).strip().lower()
    if key not in MAILJET_SYNC_LOOKBACKS:
        key = DEFAULT_MAILJET_SYNC_LOOKBACK
    return key


def mailjet_sync_lookback_cutoff(lookback_key):
    key = normalize_mailjet_sync_lookback(lookback_key)
    spec = MAILJET_SYNC_LOOKBACKS.get(key) or MAILJET_SYNC_LOOKBACKS[DEFAULT_MAILJET_SYNC_LOOKBACK]
    return _ensure_aware_utc(datetime.now(timezone.utc) - timedelta(seconds=int(spec.get("seconds", 86400))))


def _mailjet_record_event_dt(record):
    if not isinstance(record, dict):
        return None
    dt = parse_iso_datetime(
        record.get("last_event_at")
        or record.get("SendEndAt")
        or record.get("CreatedAt")
        or record.get("ArrivedAt")
        or record.get("LastActivityAt")
    )
    return _ensure_aware_utc(dt)


def _mailjet_record_in_lookback(record, cutoff_dt):
    if not cutoff_dt:
        return True
    event_dt = _mailjet_record_event_dt(record)
    if not event_dt:
        return True
    return event_dt >= cutoff_dt


def monitor_next_run_iso(monitor_cfg):
    if not monitor_cfg.get("enabled"):
        return None
    frequency = monitor_cfg.get("frequency", "weekly")
    hours = MONITOR_FREQUENCIES.get(frequency, MONITOR_FREQUENCIES["weekly"])["hours"]
    last_run = parse_iso_datetime(monitor_cfg.get("last_full_scan"))
    if not last_run:
        return datetime.now().isoformat()
    return (last_run + timedelta(hours=hours)).isoformat()


def _default_warmup_schedule_config():
    return {
        "enabled": False,
        "frequency": "daily",
        "interval_days": 1,
        "sender_local_part": "noreply",
        "from_name": "",
        "to_emails": [],
        "selected_domains": [],
        "count": 1,
        "last_run_at": None,
        "last_error": "",
        "last_result": {},
    }


def _sanitize_warmup_schedule_config(raw):
    merged = _default_warmup_schedule_config()
    if isinstance(raw, dict):
        merged.update(raw)
    merged["enabled"] = bool(merged.get("enabled"))
    frequency = str(merged.get("frequency") or "daily").lower()
    if frequency not in WARMUP_FREQUENCIES:
        frequency = "daily"
    merged["frequency"] = frequency
    merged["interval_days"] = max(1, min(_safe_int(merged.get("interval_days"), 1) or 1, 30))
    local_part = str(merged.get("sender_local_part") or "noreply").strip().lower()
    local_part = re.sub(r"[^a-z0-9._+-]", "", local_part)
    merged["sender_local_part"] = local_part or "noreply"
    merged["from_name"] = str(merged.get("from_name") or "").strip()
    to_emails = merged.get("to_emails") or []
    if isinstance(to_emails, str):
        to_emails = [line.strip() for line in to_emails.splitlines() if line.strip()]
    elif isinstance(to_emails, list):
        to_emails = [str(x).strip() for x in to_emails if str(x).strip()]
    else:
        to_emails = []
    merged["to_emails"] = to_emails
    selected_domains = merged.get("selected_domains") or []
    if isinstance(selected_domains, str):
        selected_domains = re.split(r"[\s,]+", selected_domains)
    if isinstance(selected_domains, list):
        cleaned = []
        seen = set()
        for item in selected_domains:
            name = str(item or "").strip().lower()
            if not name or name in seen:
                continue
            if not DOMAIN_REGEX.match(name):
                continue
            seen.add(name)
            cleaned.append(name)
        selected_domains = cleaned
    else:
        selected_domains = []
    merged["selected_domains"] = selected_domains
    merged["count"] = max(1, min(_safe_int(merged.get("count"), 1) or 1, 5))
    merged["last_run_at"] = merged.get("last_run_at")
    merged["last_error"] = str(merged.get("last_error") or "")
    merged["last_result"] = merged.get("last_result") if isinstance(merged.get("last_result"), dict) else {}
    return merged


def get_warmup_schedule_config():
    cfg = load_config()
    raw = cfg.get("warmup_schedule") or {}
    return _sanitize_warmup_schedule_config(raw)


def save_warmup_schedule_config(schedule_cfg):
    cfg = load_config()
    existing = get_warmup_schedule_config()
    merged = dict(existing)
    if isinstance(schedule_cfg, dict):
        merged.update(schedule_cfg)
    cfg["warmup_schedule"] = _sanitize_warmup_schedule_config(merged)
    save_config(cfg)
    return get_warmup_schedule_config()


def warmup_next_run_iso(schedule_cfg):
    if not schedule_cfg.get("enabled"):
        return None
    interval_days = max(1, min(_safe_int(schedule_cfg.get("interval_days"), 1) or 1, 30))
    hours = interval_days * 24
    last_run = parse_iso_datetime(schedule_cfg.get("last_run_at"))
    if not last_run:
        return datetime.now().isoformat()
    return (last_run + timedelta(hours=hours)).isoformat()


def ensure_domain_scan_state(state, domain):
    entry = state.setdefault("domains", {}).setdefault(domain, {})
    entry.setdefault("health", {})
    entry.setdefault("reputation", {})
    entry.setdefault("categorization", {})
    entry.setdefault("history", {"health": [], "reputation": [], "categorization": [], "categorization_submit": []})
    entry["history"].setdefault("health", [])
    entry["history"].setdefault("reputation", [])
    entry["history"].setdefault("categorization", [])
    entry["history"].setdefault("categorization_submit", [])
    return entry


def append_history(history_list, item, limit=30):
    history_list.append(item)
    if len(history_list) > limit:
        del history_list[:-limit]


DEFAULT_CATEGORY_PATTERNS = [
    r"category\s*[:\-]\s*([A-Za-z0-9 /&()\-]{2,80})",
    r"categorized\s+as\s+([A-Za-z0-9 /&()\-]{2,80})",
    r"content\s+category\s*[:\-]\s*([A-Za-z0-9 /&()\-]{2,80})",
]
DEFAULT_REPUTATION_PATTERNS = [
    r"reputation\s*[:\-]\s*([A-Za-z0-9 /&()\-]{2,80})",
    r"risk\s*level\s*[:\-]\s*([A-Za-z0-9 /&()\-]{2,80})",
    r"safety\s*[:\-]\s*([A-Za-z0-9 /&()\-]{2,80})",
]
CHALLENGE_MARKERS = ("captcha", "turnstile", "cloudflare", "human verification", "just a moment")
LOGIN_MARKERS = ("sign in", "log in", "login", "authentication", "you must be logged in")
BROWSER_FALLBACK_PROVIDERS = {
    "trendmicro",
    "mcafee",
    "bluecoat",
    "talosintelligence",
}
LIGHTSPEED_PROXY_URL = "https://production-archive-proxy-api.lightspeedsystems.com/archiveproxy"
LIGHTSPEED_PROXY_API_KEY = "onEkoztnFpTi3VG7XQEq6skQWN3aFm3h"
LIGHTSPEED_CATEGORY_CACHE = {"updated_at": 0.0, "map": {}}
HTTP_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


def _flatten_json_text(value, output):
    if len(output) >= 300:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            output.append(str(k))
            _flatten_json_text(v, output)
    elif isinstance(value, list):
        for item in value:
            _flatten_json_text(item, output)
    elif value is not None:
        output.append(str(value))


def _normalize_whitespace(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _extract_match(text, patterns):
    for pattern in patterns:
        try:
            match = re.search(pattern, text, flags=re.IGNORECASE)
        except re.error:
            continue
        if not match:
            continue
        candidate = _normalize_whitespace(match.group(1))
        if not candidate:
            continue
        lowered = candidate.lower()
        if lowered in ("unknown", "none", "n/a", "na"):
            continue
        if len(candidate) > 90:
            continue
        return candidate
    return ""


def _response_to_text(response):
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "application/json" in content_type:
        try:
            payload = response.json()
            buffer = []
            _flatten_json_text(payload, buffer)
            return " ".join(buffer)
        except Exception:
            return response.text or ""
    raw = response.text or ""
    # Remove noisy script/style and tags for easier extraction.
    raw = re.sub(r"<script.*?</script>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
    raw = re.sub(r"<style.*?</style>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
    raw = re.sub(r"<[^>]+>", " ", raw)
    return raw


def _provider_from_key(key):
    return CATEGORIZATION_PROVIDERS.get((key or "").strip().lower())


def _scan_result(provider, status="error", message="", checked_url="", http_code=None, category="", reputation="", latency_ms=0, method="http", **extra):
    payload = {
        "vendor": provider.get("key", ""),
        "service": provider.get("name", provider.get("key", "")),
        "status": status,
        "checked_url": checked_url,
        "http_code": http_code,
        "category": category or "",
        "reputation": reputation or "",
        "message": message or "",
        "latency_ms": int(latency_ms or 0),
        "method": method,
    }
    payload.update(extra or {})
    return payload


def _categorization_browser_fallback_enabled(cfg=None):
    cfg = cfg or load_config()
    raw = cfg.get("categorization_browser_fallback", True)
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() not in ("0", "false", "no", "off")


def _browser_ready():
    return bool(SBDriver and By and WebDriverWait and EC)


def _looks_like_challenge(text):
    lower = (text or "").lower()
    challenge_hints = (
        "access is denied due to automated program detection",
        "please verify captcha",
        "captcha validation error",
        "failed recaptcha",
        "blocked automated program",
    )
    return any(marker in lower for marker in CHALLENGE_MARKERS + challenge_hints)


def _looks_like_login(text):
    lower = (text or "").lower()
    return any(marker in lower for marker in LOGIN_MARKERS)


def _open_browser_driver(timeout=45):
    if not _browser_ready():
        return None
    driver = SBDriver(uc=True, headless=True)
    try:
        driver.set_page_load_timeout(timeout)
    except Exception:
        pass
    return driver


def _wait_css(driver, selector, timeout=12):
    return WebDriverWait(driver, timeout).until(EC.presence_of_element_located((By.CSS_SELECTOR, selector)))


def _safe_css_text(driver, selector):
    try:
        return _normalize_whitespace(driver.find_element(By.CSS_SELECTOR, selector).text)
    except Exception:
        return ""


def _safe_body_text(driver):
    try:
        return driver.find_element(By.TAG_NAME, "body").text
    except Exception:
        return ""


def _extract_following_line(text, marker, max_hops=6):
    lines = [_normalize_whitespace(line) for line in (text or "").splitlines()]
    lines = [line for line in lines if line]
    skip_terms = ("last time rated", "if you feel", "do you agree", "note:", "copyright", "?")
    marker_lower = marker.lower()
    for idx, line in enumerate(lines):
        if marker_lower not in line.lower():
            continue
        for candidate in lines[idx + 1:idx + 1 + max_hops]:
            low = candidate.lower()
            if any(term in low for term in skip_terms):
                continue
            return candidate
    return ""


def _friendly_category_label(label):
    text = str(label or "").strip()
    if not text:
        return ""
    return text.replace("-", " ").strip()


def _lightspeed_category_map(timeout=25):
    cache = LIGHTSPEED_CATEGORY_CACHE
    now_ts = time.time()
    if cache.get("map") and (now_ts - cache.get("updated_at", 0)) < 86400:
        return cache["map"]

    category_map = {}
    try:
        session = requests.Session()
        session.headers.update(HTTP_BROWSER_HEADERS)
        homepage = session.get("https://archive.lightspeedsystems.com/", timeout=timeout)
        script_match = re.search(r'<script[^>]+src="(/assets/index-[^"]+\.js)"', homepage.text, flags=re.IGNORECASE)
        if script_match:
            js_url = urljoin("https://archive.lightspeedsystems.com/", script_match.group(1))
            js_payload = session.get(js_url, timeout=timeout).text
            for cat_num, cat_name, cat_desc in re.findall(
                r'CategoryNumber:(\d+),CategoryName:"([^"]+)",CategoryDescription:"([^"]*)"',
                js_payload,
            ):
                category_map[int(cat_num)] = {
                    "name": _friendly_category_label(cat_name),
                    "description": _normalize_whitespace(cat_desc),
                }
    except Exception:
        category_map = cache.get("map", {}) or {}

    cache["updated_at"] = now_ts
    cache["map"] = category_map
    return category_map


def _lightspeed_category_name(category_id):
    if category_id is None:
        return ""
    try:
        cat_id = int(category_id)
    except (TypeError, ValueError):
        return ""
    category_info = _lightspeed_category_map().get(cat_id)
    if category_info:
        return category_info.get("name", "")
    return f"Category {cat_id}"


def _check_lightspeed_archive(provider, domain, timeout=25):
    started = time.time()
    query = """query getDeviceCategorization($itemA: CustomHostLookupInput!, $itemB: CustomHostLookupInput!){
  a: custom_HostLookup(item: $itemA) {
    request { host }
    cat
    action
    source_ip
    archive_info {
      filter { category transTime reason isSafetyTable isTLD }
      rocket { category }
    }
  }
  b: custom_HostLookup(item: $itemB) {
    request { host }
    cat
    action
    source_ip
    archive_info {
      filter { category transTime reason }
      rocket { category }
    }
  }
}"""
    payload = {
        "query": query,
        "variables": {
            "itemA": {"hostname": domain, "getArchive": True},
            "itemB": {"hostname": domain, "getArchive": True},
        },
    }
    headers = dict(HTTP_BROWSER_HEADERS)
    headers.update({"x-api-key": LIGHTSPEED_PROXY_API_KEY, "Content-Type": "application/json"})

    try:
        resp = requests.post(LIGHTSPEED_PROXY_URL, json=payload, headers=headers, timeout=timeout)
    except Exception as exc:
        return _scan_result(
            provider,
            status="error",
            checked_url=LIGHTSPEED_PROXY_URL,
            message=f"Lightspeed API request failed: {exc}",
            latency_ms=int((time.time() - started) * 1000),
            method="lightspeed_api",
        )

    if resp.status_code >= 400:
        status = "challenge" if resp.status_code in (401, 403, 429) else "error"
        return _scan_result(
            provider,
            status=status,
            checked_url=LIGHTSPEED_PROXY_URL,
            http_code=resp.status_code,
            message=f"Lightspeed API returned HTTP {resp.status_code}",
            latency_ms=int((time.time() - started) * 1000),
            method="lightspeed_api",
        )

    try:
        payload = resp.json()
    except Exception as exc:
        return _scan_result(
            provider,
            status="error",
            checked_url=LIGHTSPEED_PROXY_URL,
            http_code=resp.status_code,
            message=f"Invalid Lightspeed API response: {exc}",
            latency_ms=int((time.time() - started) * 1000),
            method="lightspeed_api",
        )

    if payload.get("errors"):
        message = _normalize_whitespace("; ".join(err.get("message", "") for err in payload.get("errors", [])))
        return _scan_result(
            provider,
            status="error",
            checked_url=LIGHTSPEED_PROXY_URL,
            http_code=resp.status_code,
            message=message or "Lightspeed GraphQL returned errors.",
            latency_ms=int((time.time() - started) * 1000),
            method="lightspeed_api",
        )

    lookup = ((payload.get("data") or {}).get("a") or {})
    archive_info = lookup.get("archive_info") or {}
    filter_info = archive_info.get("filter") or {}
    rocket_info = archive_info.get("rocket") or {}
    filter_cat = filter_info.get("category")
    rocket_cat = rocket_info.get("category")

    category_name = _lightspeed_category_name(filter_cat)
    rocket_name = _lightspeed_category_name(rocket_cat)
    reason = _normalize_whitespace(filter_info.get("reason", ""))
    reputation = ""
    if rocket_name:
        reputation = f"Rocket: {rocket_name}"

    if category_name:
        message = "Categorization data captured from Lightspeed archive API."
        if reason:
            message = f"{message} {reason}"
        return _scan_result(
            provider,
            status="checked",
            checked_url=LIGHTSPEED_PROXY_URL,
            http_code=resp.status_code,
            category=category_name,
            reputation=reputation,
            message=message,
            latency_ms=int((time.time() - started) * 1000),
            method="lightspeed_api",
            category_id=filter_cat,
            rocket_category_id=rocket_cat,
            updated_at=filter_info.get("transTime"),
        )

    return _scan_result(
        provider,
        status="reachable",
        checked_url=LIGHTSPEED_PROXY_URL,
        http_code=resp.status_code,
        message="Lightspeed API reachable, but no category value returned.",
        latency_ms=int((time.time() - started) * 1000),
        method="lightspeed_api",
    )


def run_categorization_provider_quick_check(provider_key, domain, timeout=25):
    provider = _provider_from_key(provider_key)
    if not provider:
        return _scan_result(
            {"key": provider_key, "name": provider_key},
            status="error",
            message="Unknown provider.",
            method="http",
        )

    if provider.get("key") == "lightspeedsystems":
        return _check_lightspeed_archive(provider, domain, timeout=timeout)

    started = time.time()
    check_url = (provider.get("check_url") or "").format(domain=domain)
    method = (provider.get("check_method") or "get").lower()
    payload = {
        key: str(value).format(domain=domain)
        for key, value in (provider.get("check_payload") or {}).items()
    }
    session = requests.Session()
    session.headers.update(HTTP_BROWSER_HEADERS)

    try:
        if method == "post":
            resp = session.post(check_url, data=payload, timeout=timeout, allow_redirects=True)
        else:
            resp = session.get(check_url, timeout=timeout, allow_redirects=True)
    except Exception as exc:
        return _scan_result(
            provider,
            status="error",
            checked_url=check_url,
            message=str(exc),
            latency_ms=int((time.time() - started) * 1000),
            method="http",
        )

    text = _normalize_whitespace(_response_to_text(resp))
    lowered = text.lower()
    category = _extract_match(text, (provider.get("category_patterns") or []) + DEFAULT_CATEGORY_PATTERNS)
    reputation = _extract_match(text, (provider.get("reputation_patterns") or []) + DEFAULT_REPUTATION_PATTERNS)
    if provider.get("key") == "zvelo":
        # zvelo's public page includes static category catalog text that can cause false positives.
        if category and any(marker in lowered for marker in ("aggressive anonymizer", "suggest a category", "failed recaptcha")):
            category = ""
        if category and len(category.split()) > 8:
            category = ""

    status = "reachable"
    message = "Provider reachable, no category extracted."
    if resp.status_code >= 400:
        if resp.status_code in (401, 403, 429) or _looks_like_challenge(lowered):
            status = "challenge"
            message = f"Provider blocked automated request (HTTP {resp.status_code})."
        else:
            status = "error"
            message = f"HTTP {resp.status_code}"
    elif _looks_like_challenge(lowered):
        status = "challenge"
        message = "Challenge page detected (captcha/anti-bot)."
    elif provider.get("requires_auth") and _looks_like_login(lowered):
        status = "auth_required"
        message = "Provider requires authenticated session."
    elif category or reputation:
        status = "checked"
        message = "Categorization data captured."

    return _scan_result(
        provider,
        status=status,
        checked_url=check_url,
        http_code=resp.status_code,
        category=category,
        reputation=reputation,
        message=message,
        latency_ms=int((time.time() - started) * 1000),
        method="http",
    )


def _browser_check_trendmicro(driver, provider, domain):
    check_url = provider.get("portal_url") or provider.get("check_url", "")
    driver.get(check_url)
    time.sleep(2)
    input_el = _wait_css(driver, "#urlname", timeout=18)
    input_el.clear()
    input_el.send_keys(domain)
    submit_el = _wait_css(driver, "#getinfo", timeout=12)
    driver.execute_script("arguments[0].click();", submit_el)
    time.sleep(6)
    body = _safe_body_text(driver)
    category = _safe_css_text(driver, ".labeltitlesmallresult")
    reputation = _safe_css_text(driver, ".labeltitleresult")
    if category or reputation:
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category=category, reputation=reputation, message="Category extracted via browser flow.", method="browser_uc")
    if _looks_like_challenge(body):
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="TrendMicro lookup blocked by challenge.", method="browser_uc")
    return _scan_result(provider, status="reachable", checked_url=driver.current_url, message="TrendMicro loaded, no category extracted.", method="browser_uc")


def _browser_check_mcafee(driver, provider, domain):
    check_url = provider.get("portal_url") or provider.get("check_url", "")
    driver.get(check_url)
    time.sleep(2)
    input_el = _wait_css(driver, "input[name='url']", timeout=18)
    input_el.clear()
    input_el.send_keys(domain)
    submit_el = _wait_css(driver, "input[type='submit']", timeout=12)
    driver.execute_script("arguments[0].click();", submit_el)
    time.sleep(6)
    body = _safe_body_text(driver)
    if _looks_like_challenge(body):
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="McAfee blocked the automated lookup.", method="browser_uc")
    category = ""
    category_match = re.search(r"Categorized URL\s*-\s*([^\n\r]+)", body, flags=re.IGNORECASE)
    if category_match:
        category = _normalize_whitespace(category_match.group(1))
    reputation = ""
    rep_match = re.search(r"\b(Minimal|Low|Medium|High|Unverified)\s+Risk\b", body, flags=re.IGNORECASE)
    if rep_match:
        reputation = _normalize_whitespace(rep_match.group(0))
    if category or reputation:
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category=category, reputation=reputation, message="Category extracted via browser flow.", method="browser_uc")
    return _scan_result(provider, status="reachable", checked_url=driver.current_url, message="McAfee lookup loaded, no category extracted.", method="browser_uc")


def _browser_check_bluecoat(driver, provider, domain):
    check_url = provider.get("portal_url") or provider.get("check_url", "")
    driver.get(check_url)
    time.sleep(4)
    input_el = _wait_css(driver, "#txtUrl", timeout=25)
    input_el.clear()
    input_el.send_keys(domain)
    submit_el = _wait_css(driver, "#btnLookup", timeout=15)
    driver.execute_script("arguments[0].click();", submit_el)
    time.sleep(7)
    body = _safe_body_text(driver)
    if _looks_like_challenge(body):
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="Bluecoat requires human/captcha validation.", method="browser_uc")
    if "not yet been rated" in body.lower():
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category="NONE", message="Domain not yet rated by Bluecoat.", method="browser_uc")
    category = _extract_following_line(body, "current categorization:")
    if category:
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category=category, message="Category extracted via browser flow.", method="browser_uc")
    return _scan_result(provider, status="reachable", checked_url=driver.current_url, message="Bluecoat lookup loaded, no category extracted.", method="browser_uc")


def _browser_check_talos(driver, provider, domain):
    lookup_url = f"https://talosintelligence.com/reputation_center/lookup?search={quote(domain, safe='')}"
    if hasattr(driver, "uc_open_with_reconnect"):
        driver.uc_open_with_reconnect(lookup_url, reconnect_time=10)
    else:
        driver.get(lookup_url)
    time.sleep(6)
    body = _safe_body_text(driver)
    category = _safe_css_text(driver, ".content-category")
    reputation = _safe_css_text(driver, ".new-legacy-label.capitalize")
    if category or reputation:
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category=category, reputation=reputation, message="Category extracted via browser flow.", method="browser_uc")
    if _looks_like_login(body):
        return _scan_result(provider, status="auth_required", checked_url=driver.current_url, message="Talos lookup requires authentication.", method="browser_uc")
    if _looks_like_challenge(body):
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="Talos lookup blocked by challenge.", method="browser_uc")
    return _scan_result(provider, status="reachable", checked_url=driver.current_url, message="Talos lookup loaded, no category extracted.", method="browser_uc")


def _browser_check_brightcloud(driver, provider, domain):
    check_url = provider.get("portal_url") or provider.get("check_url", "")
    driver.get(check_url)
    time.sleep(2)
    input_el = _wait_css(driver, "#searchBox", timeout=20)
    input_el.clear()
    input_el.send_keys(domain)
    submit_el = _wait_css(driver, ".btn.btn-base", timeout=12)
    driver.execute_script("arguments[0].click();", submit_el)
    time.sleep(6)
    body = _safe_body_text(driver)
    if _looks_like_challenge(body):
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="BrightCloud requires CAPTCHA verification.", method="browser_uc")
    category = _extract_match(body, [r"Web Category:\s*([^\n\r]+)"])
    reputation = _extract_match(body, [r"Threat Score:\s*([^\n\r]+)"])
    if category or reputation:
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category=category, reputation=reputation, message="Category extracted via browser flow.", method="browser_uc")
    return _scan_result(provider, status="reachable", checked_url=driver.current_url, message="BrightCloud lookup loaded, no category extracted.", method="browser_uc")


def _browser_check_paloalto(driver, provider, domain):
    check_url = provider.get("portal_url") or provider.get("check_url", "")
    driver.get(check_url)
    time.sleep(2)
    input_el = _wait_css(driver, "#id_url", timeout=18)
    input_el.clear()
    input_el.send_keys(domain)
    submit_el = _wait_css(driver, "button[type='submit']", timeout=12)
    driver.execute_script("arguments[0].click();", submit_el)
    time.sleep(7)
    body = _safe_body_text(driver)
    if "captcha validation error" in body.lower() or _looks_like_challenge(body):
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="Palo Alto lookup requires CAPTCHA validation.", method="browser_uc")
    category = _extract_match(body, [r"Categories:\s*([^\n\r]+)"])
    reputation = _extract_match(body, [r"Risk Level:\s*([^\n\r]+)"])
    if category or reputation:
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category=category, reputation=reputation, message="Category extracted via browser flow.", method="browser_uc")
    return _scan_result(provider, status="reachable", checked_url=driver.current_url, message="Palo Alto lookup loaded, no category extracted.", method="browser_uc")


def _browser_check_zvelo(driver, provider, domain):
    check_url = provider.get("portal_url") or provider.get("check_url", "")
    driver.get(check_url)
    time.sleep(3)
    input_el = _wait_css(driver, "#zvelo-search-input", timeout=22)
    input_el.clear()
    input_el.send_keys(domain)
    driver.execute_script("document.getElementById('zvelo-search-button').disabled = false;")
    submit_el = _wait_css(driver, "#zvelo-search-button", timeout=12)
    driver.execute_script("arguments[0].click();", submit_el)
    time.sleep(8)
    result_items = []
    try:
        result_items = [
            _normalize_whitespace(item.text)
            for item in driver.find_elements(By.CSS_SELECTOR, "#zvelo-search-results li")
            if _normalize_whitespace(item.text)
        ]
    except Exception:
        result_items = []
    body = _safe_body_text(driver)
    if any("failed recaptcha" in item.lower() or item.upper() == "ERROR" for item in result_items) or _looks_like_challenge(body):
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="zvelo lookup requires CAPTCHA verification.", method="browser_uc")
    candidates = [item for item in result_items if "categorization results" not in item.lower()]
    category = candidates[0] if candidates else ""
    if category:
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category=category, message="Category extracted via browser flow.", method="browser_uc")
    return _scan_result(provider, status="reachable", checked_url=driver.current_url, message="zvelo lookup loaded, no category extracted.", method="browser_uc")


def _browser_check_watchguard(driver, provider, domain, cfg):
    username = str(cfg.get("watchguard_username", "")).strip()
    password = str(cfg.get("watchguard_password", "")).strip()
    if not username or not password:
        return _scan_result(provider, status="auth_required", checked_url=provider.get("check_url", ""), message="WatchGuard credentials are required in Settings.", method="browser_uc")

    check_url = provider.get("check_url", "")
    driver.get(check_url)
    time.sleep(3)
    if "wglogin.watchguard.com" in (driver.current_url or ""):
        try:
            user_el = _wait_css(driver, "#signInName", timeout=15)
            pass_el = _wait_css(driver, "#password", timeout=12)
            user_el.clear()
            user_el.send_keys(username)
            pass_el.clear()
            pass_el.send_keys(password)
            login_btn = _wait_css(driver, "#continue", timeout=12)
            driver.execute_script("arguments[0].click();", login_btn)
            time.sleep(8)
        except Exception:
            return _scan_result(provider, status="auth_required", checked_url=driver.current_url, message="Unable to complete WatchGuard login flow.", method="browser_uc")

    if "wglogin.watchguard.com" in (driver.current_url or ""):
        return _scan_result(provider, status="auth_required", checked_url=driver.current_url, message="WatchGuard login not completed (MFA/session required).", method="browser_uc")

    driver.get(check_url)
    time.sleep(2)
    try:
        input_el = _wait_css(driver, "#urlList", timeout=15)
        input_el.clear()
        input_el.send_keys(domain)
        submit_el = _wait_css(driver, "#searchUrlCategories", timeout=12)
        driver.execute_script("arguments[0].click();", submit_el)
        time.sleep(8)
    except Exception:
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="WatchGuard lookup blocked by login/captcha workflow.", method="browser_uc")

    body = _safe_body_text(driver)
    if _looks_like_challenge(body):
        return _scan_result(provider, status="challenge", checked_url=driver.current_url, message="WatchGuard lookup requires CAPTCHA verification.", method="browser_uc")
    category = _extract_match(body, [r"categorized as\s*([^\n\r]+)"])
    if "not categorized" in body.lower():
        category = "NONE"
    if category:
        return _scan_result(provider, status="checked", checked_url=driver.current_url, category=category, message="Category extracted via browser flow.", method="browser_uc")
    return _scan_result(provider, status="reachable", checked_url=driver.current_url, message="WatchGuard lookup loaded, no category extracted.", method="browser_uc")


def run_categorization_provider_browser_check(provider_key, domain, cfg=None, timeout=45):
    provider = _provider_from_key(provider_key)
    if not provider:
        return _scan_result({"key": provider_key, "name": provider_key}, status="error", message="Unknown provider.", method="browser_uc")
    if provider["key"] not in BROWSER_FALLBACK_PROVIDERS:
        return _scan_result(provider, status="reachable", message="No browser fallback defined for provider.", method="browser_uc")
    if not _browser_ready():
        return _scan_result(provider, status="error", message="Browser fallback unavailable: seleniumbase/selenium not installed.", method="browser_uc")

    started = time.time()
    driver = _open_browser_driver(timeout=timeout)
    if not driver:
        return _scan_result(provider, status="error", message="Browser fallback unavailable.", method="browser_uc")
    cfg = cfg or load_config()
    try:
        key = provider["key"]
        if key == "trendmicro":
            result = _browser_check_trendmicro(driver, provider, domain)
        elif key == "mcafee":
            result = _browser_check_mcafee(driver, provider, domain)
        elif key == "bluecoat":
            result = _browser_check_bluecoat(driver, provider, domain)
        elif key == "talosintelligence":
            result = _browser_check_talos(driver, provider, domain)
        elif key == "brightcloud":
            result = _browser_check_brightcloud(driver, provider, domain)
        elif key == "paloalto":
            result = _browser_check_paloalto(driver, provider, domain)
        elif key == "zvelo":
            result = _browser_check_zvelo(driver, provider, domain)
        elif key == "watchguard":
            result = _browser_check_watchguard(driver, provider, domain, cfg)
        else:
            result = _scan_result(provider, status="reachable", message="No browser fallback implemented for provider.", method="browser_uc")
    except Exception as exc:
        result = _scan_result(
            provider,
            status="error",
            checked_url=provider.get("check_url", ""),
            message=f"Browser fallback failed: {exc}",
            method="browser_uc",
        )
    finally:
        try:
            driver.quit()
        except Exception:
            pass

    result["latency_ms"] = int((time.time() - started) * 1000)
    return result


def _merge_provider_results(primary, secondary):
    if not secondary:
        return primary
    if secondary.get("status") == "checked":
        return secondary
    if primary.get("status") == "checked":
        return primary
    if secondary.get("status") in ("challenge", "auth_required") and primary.get("status") in ("error", "reachable", "challenge"):
        return secondary
    if primary.get("status") == "error" and secondary.get("status") != "error":
        return secondary
    merged = dict(primary)
    alt_message = secondary.get("message")
    if alt_message:
        merged["message"] = f"{primary.get('message', '')} Browser fallback: {alt_message}".strip()
    return merged


def run_categorization_provider_check(provider_key, domain, timeout=25, cfg=None):
    cfg = cfg or load_config()
    quick = run_categorization_provider_quick_check(provider_key, domain, timeout=timeout)
    if quick.get("status") == "checked":
        return quick
    if not _categorization_browser_fallback_enabled(cfg):
        return quick
    if (provider_key or "").strip().lower() not in BROWSER_FALLBACK_PROVIDERS:
        return quick
    browser = run_categorization_provider_browser_check(provider_key, domain, cfg=cfg, timeout=max(35, timeout))
    return _merge_provider_results(quick, browser)


def run_categorization_scan(domain, provider_keys=None):
    cfg = load_config()
    keys = provider_keys or CATEGORIZATION_PROVIDER_ORDER
    selected = [key for key in keys if key in CATEGORIZATION_PROVIDERS]
    if not selected:
        return {"domain": domain, "scanned_at": datetime.now().isoformat(), "results": []}

    results_by_vendor = {}
    max_workers = min(4, len(selected))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(run_categorization_provider_quick_check, key, domain): key
            for key in selected
        }
        for future in as_completed(future_map):
            try:
                item = future.result()
                results_by_vendor[item.get("vendor")] = item
            except Exception as exc:
                key = future_map[future]
                provider = CATEGORIZATION_PROVIDERS.get(key, {})
                results_by_vendor[key] = _scan_result(
                    {"key": key, "name": provider.get("name", key)},
                    status="error",
                    message=str(exc),
                    method="http",
                )

    if _categorization_browser_fallback_enabled(cfg):
        for key in selected:
            current = results_by_vendor.get(key)
            if not current:
                continue
            if current.get("status") == "checked":
                continue
            if key not in BROWSER_FALLBACK_PROVIDERS:
                continue
            browser_result = run_categorization_provider_browser_check(key, domain, cfg=cfg, timeout=45)
            results_by_vendor[key] = _merge_provider_results(current, browser_result)

    results = [results_by_vendor.get(key) for key in selected if results_by_vendor.get(key)]

    order = {name: idx for idx, name in enumerate(CATEGORIZATION_PROVIDER_ORDER)}
    results.sort(key=lambda item: order.get(item.get("vendor"), 999))
    summary = {
        "checked": sum(1 for item in results if item.get("status") == "checked"),
        "reachable": sum(1 for item in results if item.get("status") == "reachable"),
        "challenge": sum(1 for item in results if item.get("status") == "challenge"),
        "auth_required": sum(1 for item in results if item.get("status") == "auth_required"),
        "errors": sum(1 for item in results if item.get("status") == "error"),
    }
    return {
        "domain": domain,
        "engine": "native_categorization_v2",
        "scanned_at": datetime.now().isoformat(),
        "results": results,
        "summary": summary,
        "browser_fallback_enabled": _categorization_browser_fallback_enabled(cfg),
    }


def run_categorization_submit(domain, target_category="", requester_email="", notes="", provider_keys=None):
    return {
        "domain": domain,
        "engine": "native_categorization_v2",
        "submitted_at": datetime.now().isoformat(),
        "disabled": True,
        "message": "Automatic categorization submission is disabled. Use manual provider links.",
        "results": [],
    }


def categorization_engine_probe(cfg=None):
    cfg = cfg or load_config()
    missing_auth = []
    if not str(cfg.get("talos_username", "")).strip() or not str(cfg.get("talos_password", "")).strip():
        missing_auth.append("Cisco Talos credentials")
    return {
        "success": True,
        "engine": "native_categorization_v2",
        "providers": [CATEGORIZATION_PROVIDERS[key]["name"] for key in CATEGORIZATION_PROVIDER_ORDER],
        "missing_auth": missing_auth,
        "browser_fallback_enabled": _categorization_browser_fallback_enabled(cfg),
        "browser_fallback_ready": _browser_ready(),
    }


def _safe_int(value, default=0):
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def assess_burned_signals(vt=None, abuse=None, urlhaus=None):
    """Return burned signal decision from reputation snapshots."""
    vt = vt or {}
    abuse = abuse or {}
    urlhaus = urlhaus or {}

    malicious = _safe_int(vt.get("malicious"), 0)
    suspicious = _safe_int(vt.get("suspicious"), 0)
    abuse_score = _safe_int(abuse.get("abuse_score"), 0)
    urlhaus_status = str(urlhaus.get("status") or "").lower()
    reasons = []

    if urlhaus_status == "flagged":
        reasons.append("URLhaus flagged malicious URLs")
    if malicious >= 10:
        reasons.append(f"VirusTotal malicious detections: {malicious}")
    if malicious >= 5 and abuse_score >= 10:
        reasons.append(f"Combined risk (VT malicious {malicious}, AbuseIPDB {abuse_score}%)")
    if (malicious + suspicious) >= 12:
        reasons.append(f"VirusTotal total risky detections: {malicious + suspicious}")
    if abuse_score >= 35:
        reasons.append(f"AbuseIPDB abuse confidence: {abuse_score}%")

    return bool(reasons), reasons


def refresh_whois_cache(domains_data, max_refresh=8):
    """Refresh cached WHOIS age fields for dashboard accuracy."""
    domains = domains_data.get("domains", [])
    if not domains:
        return False

    finder = DomainFinder()
    now = datetime.now()
    refreshed = 0
    changed = False

    for d in domains:
        last_scan = parse_iso_datetime(d.get("last_whois_scan"))
        has_age = d.get("whois_age_days") is not None
        if last_scan and (now - last_scan) < timedelta(days=3):
            continue
        if has_age and last_scan and (now - last_scan) < timedelta(days=14):
            continue
        if refreshed >= max_refresh:
            break

        refreshed += 1
        info = finder.get_whois_age(d.get("name", ""))
        age_days = info.get("age_days")
        age_years = info.get("age_years")
        creation_date = info.get("creation_date")

        if age_days is not None:
            d["whois_age_days"] = _safe_int(age_days, None)
            d["whois_age_years"] = age_years
            d["whois_creation_date"] = creation_date
            d["last_whois_scan"] = now.isoformat()
            changed = True
        elif not has_age:
            # Cache the attempt to avoid repeatedly blocking dashboard loads.
            d["last_whois_scan"] = now.isoformat()
            changed = True

    return changed


def resolve_domain_age_days(domain_entry):
    whois_age = domain_entry.get("whois_age_days")
    if whois_age is not None:
        return max(0, _safe_int(whois_age, 0)), "whois"
    try:
        purchase = datetime.strptime(domain_entry.get("purchaseDate", ""), "%Y-%m-%d")
        return max(0, (datetime.now() - purchase).days), "purchase"
    except (ValueError, TypeError):
        return 0, "unknown"


def persist_scan_snapshot_to_domains(domain, health=None, reputation=None, categorization=None):
    domains_data = load_domains()
    updated = False
    for d in domains_data.get("domains", []):
        if d.get("name") != domain:
            continue

        if health:
            d["last_health"] = health.get("http_status")
            d["last_health_code"] = health.get("http_code")
            d["has_dns"] = bool(health.get("has_dns"))
            d["has_spf"] = bool(health.get("has_spf"))
            d["has_dkim"] = bool(health.get("has_dkim"))
            d["has_dmarc"] = bool(health.get("has_dmarc"))
            d["last_health_scan"] = health.get("scanned_at")
            updated = True

        if reputation:
            vt = reputation.get("virustotal", {})
            abuse = reputation.get("abuseipdb", {})
            urlhaus = reputation.get("urlhaus", {})
            d["vt_status"] = vt.get("status")
            d["vt_malicious"] = vt.get("malicious", 0)
            d["vt_suspicious"] = vt.get("suspicious", 0)
            d["abuse_status"] = abuse.get("status")
            d["abuse_score"] = abuse.get("abuse_score", 0)
            d["urlhaus_status"] = urlhaus.get("status")
            d["last_rep_scan"] = reputation.get("scanned_at")

            whois_info = reputation.get("whois", {})
            if whois_info:
                age_days = whois_info.get("age_days")
                if age_days is not None:
                    d["whois_age_days"] = _safe_int(age_days, 0)
                    d["whois_age_years"] = whois_info.get("age_years")
                    d["whois_creation_date"] = whois_info.get("creation_date")
                    d["last_whois_scan"] = reputation.get("scanned_at")

            burned, reasons = assess_burned_signals(vt=vt, abuse=abuse, urlhaus=urlhaus)
            if burned and d.get("status") not in ("burned", "retired"):
                d["status"] = "burned"
                d["burned_at"] = reputation.get("scanned_at")
                d["burned_reason"] = "; ".join(reasons)
                note = d.get("notes", "")
                marker = f"Auto-burned: {d['burned_reason']}"
                if marker not in note:
                    d["notes"] = f"{note} | {marker}".strip(" |")
            updated = True

        if categorization:
            d["last_categorization_scan"] = categorization.get("scanned_at")
            talos_result = next(
                (
                    item for item in (categorization.get("results") or [])
                    if item.get("vendor") == "talosintelligence"
                ),
                {},
            )
            talos_category = _normalize_whitespace(talos_result.get("category", ""))
            if talos_result.get("status") == "checked" and talos_category:
                d["category_talos"] = talos_category
                d["category"] = talos_category
                d["category_source"] = "talos"
                d["category_last_updated"] = categorization.get("scanned_at")
            updated = True
        break

    if updated:
        save_domains(domains_data)


def run_health_snapshot(domain):
    http = check_domain_http(domain)
    dns = check_dns_records(domain)
    email = check_email_records(domain)
    scanned_at = datetime.now().isoformat()

    snapshot = {
        "domain": domain,
        "scanned_at": scanned_at,
        "http": http,
        "dns": dns,
        "email": email,
        "http_status": http.get("status"),
        "http_code": http.get("code"),
        "has_dns": bool(dns.get("a") or dns.get("cname")),
        "has_spf": email.get("spf", {}).get("status") == "found",
        "has_dkim": email.get("dkim", {}).get("status") == "found",
        "has_dmarc": email.get("dmarc", {}).get("status") == "found",
    }

    state = load_scan_state()
    entry = ensure_domain_scan_state(state, domain)
    entry["health"] = snapshot
    append_history(entry["history"]["health"], {
        "scanned_at": scanned_at,
        "http_status": snapshot["http_status"],
        "http_code": snapshot["http_code"],
        "has_dns": snapshot["has_dns"],
        "has_spf": snapshot["has_spf"],
        "has_dkim": snapshot["has_dkim"],
        "has_dmarc": snapshot["has_dmarc"],
    })
    save_scan_state(state)
    persist_scan_snapshot_to_domains(domain, health=snapshot)
    return snapshot


def run_reputation_snapshot(domain):
    results = check_all_categorization(domain)
    scanned_at = datetime.now().isoformat()
    whois_info = DomainFinder().get_whois_age(domain)
    indexed = {}
    for item in results:
        svc = (item.get("service") or "").lower()
        if svc == "virustotal":
            indexed["virustotal"] = item
        elif svc == "abuseipdb":
            indexed["abuseipdb"] = item
        elif svc == "urlhaus":
            indexed["urlhaus"] = item

    snapshot = {
        "domain": domain,
        "scanned_at": scanned_at,
        "results": results,
        "virustotal": indexed.get("virustotal", {}),
        "abuseipdb": indexed.get("abuseipdb", {}),
        "urlhaus": indexed.get("urlhaus", {}),
        "whois": whois_info,
    }

    state = load_scan_state()
    entry = ensure_domain_scan_state(state, domain)
    entry["reputation"] = snapshot
    append_history(entry["history"]["reputation"], {
        "scanned_at": scanned_at,
        "virustotal_status": snapshot["virustotal"].get("status"),
        "abuseipdb_status": snapshot["abuseipdb"].get("status"),
        "urlhaus_status": snapshot["urlhaus"].get("status"),
    })
    save_scan_state(state)
    persist_scan_snapshot_to_domains(domain, reputation=snapshot)
    return snapshot


def run_categorization_snapshot(domain):
    snapshot = run_categorization_scan(domain)
    state = load_scan_state()
    entry = ensure_domain_scan_state(state, domain)
    previous = entry.get("categorization", {})
    if isinstance(previous, dict) and previous.get("last_submission"):
        snapshot["last_submission"] = previous.get("last_submission")
    entry["categorization"] = snapshot
    append_history(entry["history"]["categorization"], {
        "scanned_at": snapshot.get("scanned_at"),
        "checked": snapshot.get("summary", {}).get("checked", 0),
        "challenge": snapshot.get("summary", {}).get("challenge", 0),
        "auth_required": snapshot.get("summary", {}).get("auth_required", 0),
        "errors": snapshot.get("summary", {}).get("errors", 0),
    })
    save_scan_state(state)
    persist_scan_snapshot_to_domains(domain, categorization=snapshot)
    return snapshot


def run_categorization_submit_snapshot(domain, target_category="", requester_email="", notes=""):
    snapshot = run_categorization_submit(
        domain=domain,
        target_category=target_category or "",
        requester_email=requester_email or "",
        notes=notes or "",
    )
    state = load_scan_state()
    entry = ensure_domain_scan_state(state, domain)
    entry.setdefault("categorization", {})
    entry["categorization"]["last_submission"] = snapshot
    append_history(entry["history"]["categorization_submit"], {
        "submitted_at": snapshot.get("submitted_at"),
        "target_category": snapshot.get("target_category"),
        "manual_required": sum(1 for r in snapshot.get("results", []) if r.get("status") == "manual_required"),
        "errors": sum(1 for r in snapshot.get("results", []) if r.get("status") == "error"),
    })
    save_scan_state(state)
    return snapshot


def run_full_snapshot(domain):
    return {
        "domain": domain,
        "health": run_health_snapshot(domain),
        "reputation": run_reputation_snapshot(domain),
        "categorization": run_categorization_snapshot(domain),
        "scanned_at": datetime.now().isoformat(),
    }


def run_full_snapshot_all():
    domains_data = load_domains()
    results = []
    for d in domains_data.get("domains", []):
        domain = d.get("name")
        if not domain:
            continue
        try:
            results.append(run_full_snapshot(domain))
        except Exception as e:
            results.append({"domain": domain, "error": str(e)})

    state = load_scan_state()
    state["monitor"]["last_full_scan"] = datetime.now().isoformat()
    save_scan_state(state)
    return results


def fallback_discover_domains(
    keyword="",
    category="",
    tld="com",
    min_backlinks=0,
    min_age_years=0,
    max_results=30,
    human_readable_only=True,
):
    """Fallback candidate generation when upstream source is unavailable."""
    tlds = [tld.lower().lstrip(".")] if tld else ["com", "net", "org", "io", "co"]
    seeds = []

    if keyword:
        seeds.extend(re.findall(r"[a-z0-9]+", keyword.lower()))
    if category:
        seeds.extend(CATEGORY_HINTS.get(category, []))
    if not seeds:
        seeds.extend(["atlas", "harbor", "summit", "bridge", "vector", "prime", "northstar", "oakridge"])

    suffixes = ["group", "labs", "works", "insights", "hq", "solutions", "partners", "systems", "center"]
    prefixes = ["get", "my", "go", "smart", "core", "true", "next", "first"]

    generated = []
    seen = set()
    for seed in seeds[:12]:
        for suff in suffixes:
            label = f"{seed}{suff}"
            if len(label) > 24 or label in seen:
                continue
            seen.add(label)
            generated.append(label)
        for pref in prefixes:
            label = f"{pref}{seed}"
            if len(label) > 24 or label in seen:
                continue
            seen.add(label)
            generated.append(label)

    scored = []
    for label in generated:
        if human_readable_only and not is_human_readable(label):
            continue
        digest = hashlib.sha1(label.encode("utf-8")).hexdigest()
        entropy = int(digest[:8], 16)
        backlinks = 6 + (entropy % 220)
        domain_pop = 2 + ((entropy >> 6) % 80)
        archive_age = 1 + ((entropy >> 13) % 15)
        if backlinks < min_backlinks or archive_age < min_age_years:
            continue
        for dtld in tlds:
            domain = f"{label}.{dtld}"
            score = 25
            if "-" not in label:
                score += 10
            if len(label) <= 14:
                score += 10
            if any(ch.isdigit() for ch in label):
                score -= 8
            score += min(25, backlinks // 10)
            score += min(20, domain_pop // 4)
            score += min(18, archive_age)
            score = max(0, min(100, score))
            scored.append({
                "domain": domain,
                "tld": dtld,
                "backlinks": backlinks,
                "domain_pop": domain_pop,
                "archive_age": archive_age,
                "score": score,
                "source": "fallback",
            })

    scored.sort(key=lambda item: item.get("score", 0), reverse=True)
    return scored[:max_results]


def monitor_job_wrapper():
    run_full_snapshot_all()


def _eligible_warmup_domains(selected_domains=None):
    domains_data = load_domains()
    allow = None
    if selected_domains:
        allow = {str(d).strip().lower() for d in selected_domains if str(d).strip()}
    out = []
    for item in domains_data.get("domains", []):
        name = str(item.get("name") or "").strip().lower()
        status = str(item.get("status") or "").strip().lower()
        if not name:
            continue
        if status in ("burned", "retired"):
            continue
        if allow is not None and name not in allow:
            continue
        out.append(name)
    return out


def _sorted_warmup_entries(entries):
    return sorted(
        entries or [],
        key=lambda row: str(row.get("sent_at") or row.get("last_event_at") or ""),
        reverse=True,
    )


def execute_warmup_batch(from_email, from_name, to_emails, count, source="warmup_send", batch_meta=None, sleep_between_seconds=2):
    from_email = str(from_email or "").strip()
    from_name = str(from_name or "").strip()
    recipients = []
    if isinstance(to_emails, list):
        recipients = [str(x).strip() for x in to_emails if str(x).strip()]
    elif isinstance(to_emails, str):
        recipients = [line.strip() for line in to_emails.splitlines() if line.strip()]
    count = max(1, min(_safe_int(count, 1) or 1, 5))
    if not from_email or not recipients:
        return {
            "success": False,
            "error": "from_email and to_emails required",
            "results": [],
            "summary": summarize_warmup_entries(_sorted_warmup_entries(load_email_log().get("entries", []))),
        }

    results = []
    batch_id = str(uuid.uuid4())
    send_total = min(count, len(recipients)) if recipients else 0
    for i in range(send_total):
        subject = random.choice(WARMUP_SUBJECTS)
        body = random.choice(WARMUP_BODIES)
        to = recipients[i % len(recipients)]
        result = send_warmup_email(from_email, from_name, to, subject, body)
        result["to"] = to
        result["subject"] = subject
        results.append(result)
        meta = _extract_mailjet_send_meta(result)
        initial_delivery_status = (
            result.get("delivery_status")
            or _initial_mail_delivery_status(meta.get("mailjet_status"), bool(result.get("success")))
        )
        entry = {
            "id": str(uuid.uuid4()),
            "batch_id": batch_id,
            "source": source,
            "sent_at": datetime.now().isoformat(),
            "from_email": from_email,
            "from_name": from_name,
            "to": to,
            "subject": subject,
            "success": bool(result.get("success")),
            "error": result.get("error", ""),
            "provider": result.get("provider") or get_email_provider(),
            "provider_status": result.get("provider_status") or result.get("mailjet_status"),
            "mailjet_status": result.get("mailjet_status") or meta.get("mailjet_status") or ("error" if not result.get("success") else "success"),
            "delivery_status": initial_delivery_status,
            "message_id": result.get("message_id") or meta.get("message_id"),
            "message_uuid": result.get("message_uuid") or meta.get("message_uuid"),
            "last_event_at": datetime.now().isoformat(),
        }
        if isinstance(batch_meta, dict):
            for k, v in batch_meta.items():
                if k not in entry and v is not None:
                    entry[k] = v
        append_warmup_log_entry(entry)
        if i < send_total - 1 and sleep_between_seconds:
            time.sleep(max(0, min(_safe_int(sleep_between_seconds, 0) or 0, 10)))

    log_payload = load_email_log()
    all_entries = _sorted_warmup_entries(log_payload.get("entries", []))
    return {
        "success": True,
        "results": results,
        "summary": summarize_warmup_entries(all_entries),
        "batch_id": batch_id,
    }


def run_scheduled_warmup_cycle():
    schedule_cfg = get_warmup_schedule_config()
    now_iso = datetime.now().isoformat()
    aggregate = {
        "ran_at": now_iso,
        "domains_attempted": 0,
        "domains_sent": 0,
        "domains_failed": 0,
        "messages_attempted": 0,
        "messages_accepted": 0,
        "messages_failed": 0,
        "errors": [],
    }
    if not schedule_cfg.get("enabled"):
        aggregate["error"] = "Warmup scheduler disabled"
        return {"success": False, "error": aggregate["error"], "result": aggregate}

    to_emails = schedule_cfg.get("to_emails") or []
    if not to_emails:
        aggregate["error"] = "Warmup scheduler has no test contacts configured"
        save_warmup_schedule_config({"last_run_at": now_iso, "last_error": aggregate["error"], "last_result": aggregate})
        return {"success": False, "error": aggregate["error"], "result": aggregate}

    local_part = str(schedule_cfg.get("sender_local_part") or "noreply").strip().lower()
    from_name = str(schedule_cfg.get("from_name") or "NoReply").strip() or "NoReply"
    per_domain_count = max(1, min(_safe_int(schedule_cfg.get("count"), 1) or 1, 5))
    selected_domains = schedule_cfg.get("selected_domains") or []
    domains = _eligible_warmup_domains(selected_domains=selected_domains or None)
    aggregate["domains_attempted"] = len(domains)
    aggregate["selected_domains"] = list(selected_domains)

    for domain in domains:
        from_email = f"{local_part}@{domain}"
        batch = execute_warmup_batch(
            from_email=from_email,
            from_name=from_name,
            to_emails=to_emails,
            count=per_domain_count,
            source="warmup_schedule",
            batch_meta={"scheduled": True, "scheduled_domain": domain},
            sleep_between_seconds=1,
        )
        if not batch.get("success"):
            aggregate["domains_failed"] += 1
            aggregate["errors"].append({"domain": domain, "error": batch.get("error") or "Batch failed"})
            continue
        results = batch.get("results") or []
        aggregate["messages_attempted"] += len(results)
        accepted = 0
        failed = 0
        for result in results:
            if result.get("success"):
                accepted += 1
            else:
                failed += 1
        aggregate["messages_accepted"] += accepted
        aggregate["messages_failed"] += failed
        if failed and not accepted:
            aggregate["domains_failed"] += 1
            first_err = next((r.get("error") for r in results if r.get("error")), "Warmup sends failed")
            aggregate["errors"].append({"domain": domain, "error": first_err})
        else:
            aggregate["domains_sent"] += 1

    save_warmup_schedule_config({
        "last_run_at": now_iso,
        "last_error": "" if not aggregate["errors"] else f"{aggregate['domains_failed']} domain(s) failed",
        "last_result": aggregate,
    })
    return {"success": True, "result": aggregate}


def warmup_job_wrapper():
    try:
        run_scheduled_warmup_cycle()
    except Exception as exc:
        save_warmup_schedule_config({
            "last_run_at": datetime.now().isoformat(),
            "last_error": str(exc),
            "last_result": {"ran_at": datetime.now().isoformat(), "error": str(exc)},
        })


def configure_monitor_job():
    if not monitor_scheduler:
        return
    try:
        if not monitor_scheduler.running:
            monitor_scheduler.start()
        existing = monitor_scheduler.get_job(MONITOR_JOB_ID)
        if existing:
            monitor_scheduler.remove_job(MONITOR_JOB_ID)
    except Exception:
        return

    state = load_scan_state()
    monitor_cfg = state.get("monitor", {})
    if not monitor_cfg.get("enabled"):
        return
    frequency = monitor_cfg.get("frequency", "weekly")
    hours = MONITOR_FREQUENCIES.get(frequency, MONITOR_FREQUENCIES["weekly"])["hours"]
    try:
        monitor_scheduler.add_job(
            monitor_job_wrapper,
            "interval",
            hours=hours,
            id=MONITOR_JOB_ID,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
    except Exception:
        pass


def configure_warmup_job():
    if not monitor_scheduler:
        return
    try:
        if not monitor_scheduler.running:
            monitor_scheduler.start()
        existing = monitor_scheduler.get_job(WARMUP_JOB_ID)
        if existing:
            monitor_scheduler.remove_job(WARMUP_JOB_ID)
    except Exception:
        return

    schedule_cfg = get_warmup_schedule_config()
    if not schedule_cfg.get("enabled"):
        return
    interval_days = max(1, min(_safe_int(schedule_cfg.get("interval_days"), 1) or 1, 30))
    try:
        monitor_scheduler.add_job(
            warmup_job_wrapper,
            "interval",
            hours=interval_days * 24,
            id=WARMUP_JOB_ID,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
    except Exception:
        pass


def get_warmup_schedule_status():
    cfg = get_warmup_schedule_config()
    selected_domains = cfg.get("selected_domains") or []
    all_domains = _eligible_warmup_domains()
    effective_domains = _eligible_warmup_domains(selected_domains=selected_domains or None)
    return {
        "enabled": bool(cfg.get("enabled")),
        "interval_days": max(1, min(_safe_int(cfg.get("interval_days"), 1) or 1, 30)),
        "sender_local_part": cfg.get("sender_local_part", "noreply"),
        "from_name": cfg.get("from_name", ""),
        "to_emails": cfg.get("to_emails", []),
        "selected_domains": selected_domains,
        "count": max(1, min(_safe_int(cfg.get("count"), 1) or 1, 5)),
        "last_run_at": cfg.get("last_run_at"),
        "last_error": cfg.get("last_error", ""),
        "last_result": cfg.get("last_result", {}),
        "next_run": warmup_next_run_iso(cfg),
        "domain_count": len(effective_domains),
        "all_domain_count": len(all_domains),
        "selected_domain_count": len(selected_domains),
    }


# Default company names per category
COMPANY_DEFAULTS = {
    "technology": "Technology Company",
    "consulting": "Consulting Firm",
    "finance": "Financial Services Company",
    "healthcare": "Healthcare Provider",
    "education": "Education Organization",
    "news": "News Publication",
    "marketing": "Marketing Agency",
    "ecommerce": "Online Store",
    "travel": "Travel Company",
}

DOMAIN_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$")
SITE_PAGES = ("index", "about", "services", "blog", "contact", "privacy")

CATEGORY_HINTS = {
    "technology": ("tech", "cloud", "cyber", "digital", "data", "software", "support", "it"),
    "consulting": ("consult", "advisor", "partners", "group", "strategy", "solutions"),
    "finance": ("bank", "capital", "wealth", "finance", "financial", "fund", "asset"),
    "healthcare": ("health", "medical", "clinic", "care", "hospital", "wellness"),
    "education": ("academy", "institute", "school", "learn", "training", "education"),
    "news": ("news", "daily", "times", "journal", "report", "media"),
    "marketing": ("marketing", "creative", "brand", "agency", "media"),
    "ecommerce": ("shop", "store", "retail", "market", "goods", "commerce"),
    "travel": ("travel", "trip", "tour", "vacation", "journey", "resort", "retreat"),
}

CATEGORY_PROFILES = {
    "technology": {
        "headline": "Secure Digital Transformation for Growing Teams",
        "summary": "We design cloud-first systems, automate workflows, and harden infrastructure for business continuity.",
        "services": ("Managed cloud operations", "Security architecture reviews", "Compliance-ready reporting"),
        "blog_topics": ("Platform uptime playbook", "Modern identity controls", "How to reduce cloud waste"),
        "contact_role": "Solutions Architect",
    },
    "consulting": {
        "headline": "Advisory Services Built for Complex Decisions",
        "summary": "From strategy to implementation, we help teams execute with measurable outcomes and minimal overhead.",
        "services": ("Operational assessments", "Program management", "Executive workshops"),
        "blog_topics": ("Board-ready status updates", "Risk planning templates", "Post-merger operating models"),
        "contact_role": "Client Advisor",
    },
    "finance": {
        "headline": "Financial Guidance Focused on Long-Term Performance",
        "summary": "Our analysts deliver structured planning, portfolio oversight, and decision support for changing markets.",
        "services": ("Portfolio reviews", "Treasury planning", "Quarterly market briefings"),
        "blog_topics": ("Capital planning in volatile markets", "Client reporting standards", "Tax-aware allocation tips"),
        "contact_role": "Portfolio Specialist",
    },
    "healthcare": {
        "headline": "Patient-Centered Care Operations and Telehealth Support",
        "summary": "We help care teams improve access, streamline intake, and strengthen service continuity across locations.",
        "services": ("Virtual care operations", "Patient onboarding flows", "Care team scheduling support"),
        "blog_topics": ("Improving appointment throughput", "Care coordination basics", "Telehealth workflow checklist"),
        "contact_role": "Care Coordinator",
    },
    "education": {
        "headline": "Learning Programs Designed for Real-World Outcomes",
        "summary": "We support institutions with curriculum delivery, student engagement analytics, and scalable online programs.",
        "services": ("Curriculum modernization", "Faculty enablement", "Student success dashboards"),
        "blog_topics": ("Hybrid classroom planning", "Academic program metrics", "Instructor communication cadence"),
        "contact_role": "Program Director",
    },
    "news": {
        "headline": "Coverage and Analysis for Fast-Moving Industries",
        "summary": "Our editorial desk publishes timely reporting, market context, and practical insights for decision makers.",
        "services": ("Daily briefings", "Industry reports", "Research interviews"),
        "blog_topics": ("Editorial standards checklist", "Source verification process", "Building trust with readers"),
        "contact_role": "Editorial Lead",
    },
    "marketing": {
        "headline": "Campaign Strategy with Measurable Pipeline Impact",
        "summary": "We combine positioning, content, and analytics to turn awareness into qualified opportunities.",
        "services": ("Demand generation plans", "Content production", "Attribution reporting"),
        "blog_topics": ("Campaign launch checklist", "Attribution model basics", "Creative testing framework"),
        "contact_role": "Campaign Manager",
    },
    "ecommerce": {
        "headline": "Online Retail Experiences that Convert Consistently",
        "summary": "From merchandising to checkout optimization, we help stores improve conversion and repeat revenue.",
        "services": ("Storefront optimization", "Catalog strategy", "Checkout funnel tuning"),
        "blog_topics": ("Seasonal merchandising plan", "Cart recovery ideas", "Improving first-order conversion"),
        "contact_role": "Store Operations Lead",
    },
    "travel": {
        "headline": "Travel Planning and Experiences Designed Around the Trip",
        "summary": "We help travel teams present destinations, itineraries, and booking options with clear planning and support workflows.",
        "services": ("Trip planning support", "Destination packages", "Group travel coordination"),
        "blog_topics": ("Destination page checklist", "Traveler booking FAQs", "Group trip planning timeline"),
        "contact_role": "Travel Advisor",
    },
}


def is_valid_domain(domain):
    return bool(DOMAIN_REGEX.match((domain or "").strip().lower()))


def get_available_categories():
    categories = set(COMPANY_DEFAULTS.keys())
    if TEMPLATES_DIR.is_dir():
        categories.update(d.name for d in TEMPLATES_DIR.iterdir() if d.is_dir())
    return sorted(categories)


def guess_category_from_domain(domain, repo_name=""):
    haystack = f"{domain} {repo_name}".lower()
    best = "technology"
    best_score = 0
    for category, hints in CATEGORY_HINTS.items():
        score = sum(1 for hint in hints if hint in haystack)
        if score > best_score:
            best = category
            best_score = score
    return best


def derive_company_name(domain, category):
    label = domain.split(".")[0]
    readable = re.sub(r"[^a-z0-9]+", " ", label.lower()).strip()
    words = " ".join(w.capitalize() for w in readable.split()[:4]) or "Company"
    suffixes = {
        "technology": "Solutions",
        "consulting": "Consulting Group",
        "finance": "Advisors",
        "healthcare": "Health Partners",
        "education": "Institute",
        "news": "Media Group",
        "marketing": "Creative Agency",
        "ecommerce": "Storefront",
        "travel": "Travel Co",
    }
    return f"{words} {suffixes.get(category, '')}".strip()


# ── Categorization check helpers ────────────────────────────────

CATEGORIZATION_SERVICES = [
    {
        "key": key,
        "name": CATEGORIZATION_PROVIDERS[key]["name"],
        "check_url": CATEGORIZATION_PROVIDERS[key].get("portal_url") or CATEGORIZATION_PROVIDERS[key]["check_url"].replace("{domain}", ""),
        "submit_url": CATEGORIZATION_PROVIDERS[key].get("submit_url"),
    }
    for key in MANUAL_CATEGORIZATION_PROVIDER_ORDER
]


def check_domain_http(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=15, allow_redirects=True)
        return {"status": "up", "code": r.status_code, "url": r.url}
    except requests.exceptions.SSLError:
        try:
            r = requests.get(f"http://{domain}", timeout=15, allow_redirects=True)
            return {"status": "up_no_ssl", "code": r.status_code, "url": r.url}
        except Exception:
            return {"status": "down", "code": None, "url": None}
    except Exception:
        return {"status": "down", "code": None, "url": None}


def check_dns_records(domain):
    results = {"a": [], "cname": [], "mx": [], "txt": [], "ns": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    for rtype in results:
        try:
            answers = resolver.resolve(domain, rtype.upper())
            results[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return results


def check_email_records(domain):
    findings = {
        "spf": {"status": "missing", "record": None, "issues": []},
        "dkim": {"status": "unknown", "note": "DKIM requires a selector to check"},
        "dmarc": {"status": "missing", "record": None, "issues": []},
    }
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # SPF
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=spf1"):
                findings["spf"]["status"] = "found"
                findings["spf"]["record"] = txt
                if "+all" in txt:
                    findings["spf"]["issues"].append("SPF uses +all (permits all senders) — should use ~all or -all")
                if "redirect=" not in txt and "include:" not in txt and "a" not in txt:
                    findings["spf"]["issues"].append("SPF record may be too permissive — no include/a mechanisms")
                break
    except Exception:
        pass

    # DMARC
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=DMARC1"):
                findings["dmarc"]["status"] = "found"
                findings["dmarc"]["record"] = txt
                if "p=none" in txt:
                    findings["dmarc"]["issues"].append("DMARC policy is 'none' — emails won't be rejected. Consider 'quarantine' or 'reject' after testing.")
                break
    except Exception:
        pass

    # DKIM (common selectors)
    for selector in ["default", "mailjet", "google", "k1", "selector1", "selector2", "s1", "s2"]:
        try:
            answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for r in answers:
                txt = str(r).strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    findings["dkim"]["status"] = "found"
                    findings["dkim"]["selector"] = selector
                    findings["dkim"]["record"] = txt[:120] + "..."
                    break
            if findings["dkim"]["status"] == "found":
                break
        except Exception:
            pass

    return findings


# ── GitHub helpers ──────────────────────────────────────────────


def github_configured():
    """Check if GitHub PAT and username are configured."""
    cfg = load_config()
    return bool(cfg.get("github_pat") and cfg.get("github_username"))


def github_auto_push_enabled():
    """Check if auto-push is enabled and GitHub is configured."""
    cfg = load_config()
    return cfg.get("github_auto_push", False) and github_configured()


def github_request(method, endpoint, cfg=None, params=None, json_data=None, timeout=30):
    """Make a GitHub API call. Adds PAT auth header when configured."""
    if cfg is None:
        cfg = load_config()
    pat = cfg.get("github_pat", "").strip()
    headers = {"Accept": "application/vnd.github.v3+json"}
    if pat:
        headers["Authorization"] = f"token {pat}"
    url = f"https://api.github.com{endpoint}"
    resp = requests.request(method, url, headers=headers, params=params, json=json_data, timeout=timeout)
    return resp


def github_api(method, endpoint, cfg=None, json_data=None):
    """Backward-compatible wrapper for authenticated GitHub API calls."""
    resp = github_request(method, endpoint, cfg=cfg, json_data=json_data)
    return resp


def github_push_site(domain, site_dir):
    """Create a GitHub repo and push the generated site files.
    Returns dict with success status and details.
    """
    cfg = load_config()
    username = cfg.get("github_username", "")
    pat = cfg.get("github_pat", "")
    repo_name = domain.replace(".", "-")

    if not username or not pat:
        return {"success": False, "error": "GitHub not configured"}

    # 1. Create the repo (public for free GitHub Pages)
    resp = github_api("POST", "/user/repos", cfg, {
        "name": repo_name,
        "description": f"GitHub Pages site for {domain}",
        "private": False,
        "auto_init": False,
    })

    if resp.status_code == 422:
        # Repo might already exist — that's okay, we'll push to it
        pass
    elif resp.status_code not in (200, 201):
        return {"success": False, "error": f"Failed to create repo: {resp.status_code} {resp.text[:200]}"}

    # 2. Git init, add, commit, push using subprocess
    remote_url = f"https://{pat}@github.com/{username}/{repo_name}.git"

    try:
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        cmds = [
            ["git", "init"],
            ["git", "add", "-A"],
            ["git", "commit", "-m", "Initial site deployment"],
            ["git", "branch", "-M", "main"],
            ["git", "remote", "add", "origin", remote_url],
            ["git", "push", "-u", "origin", "main", "--force"],
        ]

        for cmd in cmds:
            result = subprocess.run(
                cmd, cwd=str(site_dir), capture_output=True, text=True,
                timeout=60, env=env,
            )
            # remote add may fail if already exists, that's fine
            if result.returncode != 0 and "remote" not in " ".join(cmd):
                # If push fails because remote exists, try setting URL and force push
                if "push" in cmd:
                    subprocess.run(
                        ["git", "remote", "set-url", "origin", remote_url],
                        cwd=str(site_dir), capture_output=True, text=True, env=env,
                    )
                    result = subprocess.run(
                        ["git", "push", "-u", "origin", "main", "--force"],
                        cwd=str(site_dir), capture_output=True, text=True,
                        timeout=60, env=env,
                    )
                    if result.returncode != 0:
                        return {"success": False, "error": f"Push failed: {result.stderr[:200]}"}
                elif "commit" in cmd and "nothing to commit" in result.stdout:
                    pass  # No changes to commit is fine
                else:
                    return {"success": False, "error": f"Git error: {result.stderr[:200]}"}

        # 3. Enable GitHub Pages
        time.sleep(2)  # Brief pause for GitHub to process the push
        pages_resp = github_api("POST", f"/repos/{username}/{repo_name}/pages", cfg, {
            "source": {"branch": "main", "path": "/"},
        })
        # 409 = Pages already enabled, which is fine
        pages_enabled = pages_resp.status_code in (200, 201, 409)

        # 4. Set custom domain via API
        if pages_enabled:
            github_api("PUT", f"/repos/{username}/{repo_name}/pages", cfg, {
                "cname": domain,
                "source": {"branch": "main", "path": "/"},
            })

        return {
            "success": True,
            "repo_url": f"https://github.com/{username}/{repo_name}",
            "pages_url": f"https://{domain}",
            "pages_enabled": pages_enabled,
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Git operation timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Automated categorization / reputation checks ───────────────


def check_virustotal(domain):
    """Check domain reputation via VirusTotal API v3."""
    cfg = load_config()
    api_key = cfg.get("virustotal_api_key", "")
    if not api_key:
        return {"service": "VirusTotal", "status": "not_configured"}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})

            # Extract categories from different engines
            categories = attrs.get("categories", {})
            # Popularity ranks
            popularity = attrs.get("popularity_ranks", {})
            # Last analysis stats
            analysis_stats = attrs.get("last_analysis_stats", {})
            # Reputation score
            reputation = attrs.get("reputation", 0)
            # Last analysis results — extract vendor categories
            last_analysis = attrs.get("last_analysis_results", {})
            flagged_vendors = []
            for vendor, result in last_analysis.items():
                if result.get("category") in ("malicious", "suspicious"):
                    flagged_vendors.append({"vendor": vendor, "result": result.get("result", ""), "category": result.get("category")})

            return {
                "service": "VirusTotal",
                "status": "checked",
                "categories": categories,
                "reputation_score": reputation,
                "analysis_stats": analysis_stats,
                "flagged_vendors": flagged_vendors,
                "popularity": popularity,
                "malicious": analysis_stats.get("malicious", 0),
                "suspicious": analysis_stats.get("suspicious", 0),
                "clean": analysis_stats.get("harmless", 0) + analysis_stats.get("undetected", 0),
            }
        elif resp.status_code == 404:
            return {"service": "VirusTotal", "status": "not_found", "message": "Domain not in VirusTotal database"}
        elif resp.status_code == 429:
            return {"service": "VirusTotal", "status": "rate_limited", "message": "Rate limit exceeded (free tier: 4/min)"}
        else:
            return {"service": "VirusTotal", "status": "error", "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"service": "VirusTotal", "status": "error", "message": str(e)}


def check_abuseipdb(domain):
    """Check domain IP reputation via AbuseIPDB."""
    cfg = load_config()
    api_key = cfg.get("abuseipdb_api_key", "")
    if not api_key:
        return {"service": "AbuseIPDB", "status": "not_configured"}

    try:
        # Resolve domain to IP first
        ip = socket.gethostbyname(domain)

        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            notes = []
            ip = data.get("ipAddress") or ip
            isp_text = str(data.get("isp") or "")
            usage_text = str(data.get("usageType") or "")
            host_text = " ".join([isp_text.lower(), usage_text.lower()])
            if any(marker in host_text for marker in ("github", "cloudflare", "akamai", "fastly", "amazon", "google")):
                notes.append("Shared hosting/CDN IP; AbuseIPDB signal applies to the IP, not uniquely to this domain.")
            return {
                "service": "AbuseIPDB",
                "status": "checked",
                "ip": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "usage_type": data.get("usageType", ""),
                "is_whitelisted": data.get("isWhitelisted", False),
                "domain_name": data.get("domain", ""),
                "notes": notes,
            }
        elif resp.status_code == 429:
            return {"service": "AbuseIPDB", "status": "rate_limited", "message": "Rate limit exceeded"}
        else:
            return {"service": "AbuseIPDB", "status": "error", "message": f"HTTP {resp.status_code}"}
    except socket.gaierror:
        return {"service": "AbuseIPDB", "status": "dns_failed", "message": "Could not resolve domain to IP"}
    except Exception as e:
        return {"service": "AbuseIPDB", "status": "error", "message": str(e)}


def check_urlhaus(domain):
    """Check domain against URLhaus threat intelligence."""
    cfg = load_config()
    api_key = re.sub(r"\s+", "", str(cfg.get("urlhaus_api_key", "") or ""))
    if not api_key:
        return {"service": "URLhaus", "status": "not_configured", "message": "URLhaus Auth-Key not loaded from settings"}

    try:
        def _request(with_auth=True):
            headers = {"Accept": "application/json"}
            if with_auth:
                headers["Auth-Key"] = api_key
            return requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                headers=headers,
                data={"host": domain},
                timeout=15,
            )

        resp = _request(with_auth=True)
        auth_fallback = False
        if resp.status_code == 401:
            # Probe unauthenticated response to distinguish "missing header" behavior
            # from auth key rejection and provide clearer operator feedback.
            resp = _request(with_auth=False)
            auth_fallback = True
        if resp.status_code == 200:
            data = resp.json()
            query_status = str(data.get("query_status", "")).strip().lower()
            if query_status == "no_results":
                result = {
                    "service": "URLhaus",
                    "status": "clean",
                    "message": "No malicious URLs found for this domain",
                    "url_count": 0,
                    "urls_count": 0,
                }
                if auth_fallback:
                    result["message"] += " (Auth-Key rejected by endpoint; used unauthenticated lookup)"
                    result["auth_fallback"] = True
                return result
            elif query_status == "ok":
                urls = data.get("urls", [])
                url_count = data.get("url_count", len(urls))
                try:
                    url_count = int(url_count)
                except Exception:
                    url_count = len(urls)
                result = {
                    "service": "URLhaus",
                    "status": "flagged",
                    "url_count": url_count,
                    "urls_count": url_count,
                    "first_seen": data.get("firstseen", ""),
                    "blacklists": data.get("blacklists", {}),
                    "tags": list(set(tag for u in urls[:10] for tag in (u.get("tags") or []))),
                    "recent_urls": [{"url": u.get("url", ""), "status": u.get("url_status", ""), "threat": u.get("threat", "")} for u in urls[:5]],
                }
                if auth_fallback:
                    result["message"] = "Auth-Key rejected by endpoint; used unauthenticated lookup"
                    result["auth_fallback"] = True
                return result
            else:
                result = {"service": "URLhaus", "status": "checked", "message": query_status}
                if auth_fallback:
                    result["message"] = f"{query_status} (Auth-Key rejected by endpoint; used unauthenticated lookup)"
                    result["auth_fallback"] = True
                return result
        elif resp.status_code == 403:
            try:
                data = resp.json()
            except Exception:
                data = {}
            q = str(data.get("query_status", "")).strip()
            if q == "unknown_auth_key":
                return {"service": "URLhaus", "status": "auth_invalid", "message": "URLhaus rejected the Auth-Key", "query_status": q}
            return {"service": "URLhaus", "status": "auth_invalid", "message": f"HTTP 403", "query_status": q}
        else:
            return {"service": "URLhaus", "status": "error", "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"service": "URLhaus", "status": "error", "message": str(e)}


def check_all_categorization(domain):
    """Run all configured automated categorization checks for a domain."""
    results = [check_virustotal(domain), check_abuseipdb(domain), check_urlhaus(domain)]
    return results


def normalize_vt_category_label(label):
    text = str(label or "").strip().lower()
    if not text:
        return ""
    text = re.sub(r"\([^)]*\)", "", text).replace("_", " ")
    text = re.sub(r"[^a-z0-9/&\- ]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def infer_category_from_text(text):
    content = (text or "").lower()
    if not content:
        return None, 0

    best = None
    best_score = 0
    for category, hints in CATEGORY_HINTS.items():
        score = 0
        for hint in hints:
            if re.search(rf"\b{re.escape(hint)}\b", content):
                score += 3
            elif hint in content:
                score += 1
        if category in content:
            score += 2
        if score > best_score:
            best = category
            best_score = score
    if best_score <= 0:
        return None, 0
    return best, best_score


def fetch_category_text(domain):
    snippets = [domain]
    for url in (f"https://{domain}", f"http://{domain}"):
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
        except Exception:
            continue
        if resp.status_code >= 400:
            continue

        html = (resp.text or "")[:150_000]
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
        if title_match:
            snippets.append(re.sub(r"\s+", " ", title_match.group(1)).strip())

        meta_matches = re.findall(
            r'<meta[^>]+(?:name|property)=["\'](?:description|keywords)["\'][^>]*content=["\']([^"\']+)["\']',
            html,
            flags=re.IGNORECASE,
        )
        snippets.extend(meta_matches[:4])

        plain = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        plain = re.sub(r"<[^>]+>", " ", plain)
        plain = re.sub(r"\s+", " ", plain).strip()
        if plain:
            snippets.append(plain[:3000])
        break

    return " ".join(s for s in snippets if s)


def build_domain_categorization_intel(domain):
    """Return actionable category + threat intelligence for domain finder due diligence."""
    reputation_results = check_all_categorization(domain)
    indexed = {(item.get("service") or "").lower(): item for item in reputation_results}
    vt = indexed.get("virustotal", {})
    abuse = indexed.get("abuseipdb", {})
    urlhaus = indexed.get("urlhaus", {})

    provider_scan = run_categorization_scan(domain)
    provider_results = provider_scan.get("results", [])

    weighted_labels = {}
    sources = []
    details = []

    provider_category_count = 0
    for item in provider_results:
        category = normalize_vt_category_label(item.get("category"))
        if item.get("status") != "checked":
            continue
        if not category or category in ("unknown", "none", "n a"):
            continue
        weighted_labels[category] = weighted_labels.get(category, 0) + 2
        sources.append(item.get("service") or item.get("vendor", "vendor"))
        provider_category_count += 1

    if provider_results:
        if provider_category_count:
            details.append({
                "source": "Categorization Providers",
                "status": "checked",
                "summary": f"{provider_category_count} provider categorization result(s) captured",
            })
        else:
            details.append({
                "source": "Categorization Providers",
                "status": "partial",
                "summary": "Provider scan completed with no extractable category values.",
            })

    # Keep VirusTotal categories as secondary signal.
    vt_category_source = vt
    if not (vt_category_source.get("categories") and vt_category_source.get("status") == "checked"):
        vt_probe = check_virustotal(domain)
        if vt_probe.get("status") == "checked":
            vt_category_source = vt_probe

    if vt_category_source.get("status") == "checked":
        vt_labels = vt_category_source.get("categories") or {}
        if vt_labels:
            sources.append("VirusTotal categories")
            for label in vt_labels.values():
                normalized = normalize_vt_category_label(label)
                if normalized:
                    weighted_labels[normalized] = weighted_labels.get(normalized, 0) + 1
            details.append({
                "source": "VirusTotal",
                "status": "checked",
                "summary": f"{len(vt_labels)} categorization label(s) from VT engines",
            })
        else:
            details.append({
                "source": "VirusTotal",
                "status": "checked",
                "summary": "No category labels returned by VT engines",
            })
    else:
        details.append({
            "source": "VirusTotal",
            "status": vt_category_source.get("status", "unknown"),
            "summary": vt_category_source.get("message") or "Category feed unavailable",
        })

    # Website-content heuristic remains a fallback if vendors return sparse labels.
    heuristic_text = fetch_category_text(domain)
    heur_cat, heur_score = infer_category_from_text(heuristic_text)
    if heur_cat:
        sources.append("Website content heuristic")
        weighted_labels[heur_cat] = weighted_labels.get(heur_cat, 0) + max(1, heur_score // 3)
        details.append({
            "source": "Heuristic",
            "status": "checked",
            "summary": f"Matched '{heur_cat}' profile from domain + page content",
        })
    else:
        details.append({
            "source": "Heuristic",
            "status": "none",
            "summary": "No confident category match from page content",
        })

    labels_sorted = sorted(weighted_labels.items(), key=lambda item: (-item[1], item[0]))
    labels = [label for label, _ in labels_sorted]
    primary = labels[0] if labels else "unknown"
    top_weight = labels_sorted[0][1] if labels_sorted else 0
    if top_weight >= 4:
        confidence = "high"
    elif top_weight >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    burned, reasons = assess_burned_signals(
        vt={"malicious": vt.get("malicious", 0), "suspicious": vt.get("suspicious", 0)},
        abuse={"abuse_score": abuse.get("abuse_score", 0)},
        urlhaus={"status": urlhaus.get("status")},
    )

    return {
        "domain": domain,
        "checked_at": datetime.now().isoformat(),
        "primary_category": primary,
        "confidence": confidence,
        "labels": labels,
        "sources": sorted(set(sources)),
        "details": details,
        "provider_results": provider_results,
        "categorization_engine": {
            "engine": provider_scan.get("engine", "native_categorization_v1"),
            "success": provider_scan.get("summary", {}).get("checked", 0) > 0,
            "summary": provider_scan.get("summary", {}),
        },
        "threat": {
            "virustotal": {
                "status": vt.get("status"),
                "malicious": vt.get("malicious", 0),
                "suspicious": vt.get("suspicious", 0),
            },
            "abuseipdb": {
                "status": abuse.get("status"),
                "abuse_score": abuse.get("abuse_score", 0),
            },
            "urlhaus": {
                "status": urlhaus.get("status"),
                "urls_count": urlhaus.get("urls_count", 0),
            },
        },
        "burned_signal": burned,
        "burned_reasons": reasons,
    }


# ── Site generation ─────────────────────────────────────────────


def category_profile(category):
    return CATEGORY_PROFILES.get(category, CATEGORY_PROFILES["technology"])


def build_default_html(page, category, company_name, domain):
    profile = category_profile(category)
    page_titles = {
        "index": "Home",
        "about": "About",
        "services": "Services",
        "blog": "Insights",
        "contact": "Contact",
        "privacy": "Privacy",
    }
    nav_links = []
    for slug, label in page_titles.items():
        href = "index.html" if slug == "index" else f"{slug}.html"
        active = " class=\"active\"" if slug == page else ""
        nav_links.append(f"<a{active} href=\"{href}\">{label}</a>")
    nav_html = "\n                ".join(nav_links)

    service_cards = "\n".join(
        f"""
            <article class="card">
                <h3>{service}</h3>
                <p>{profile["summary"]}</p>
            </article>
        """.rstrip()
        for service in profile["services"]
    )

    blog_cards = "\n".join(
        f"""
            <article class="card">
                <h3>{topic}</h3>
                <p>{profile["summary"]}</p>
            </article>
        """.rstrip()
        for topic in profile["blog_topics"]
    )

    sections = {
        "index": f"""
            <section class="hero">
                <h1>{profile["headline"]}</h1>
                <p>{profile["summary"]}</p>
                <a class="btn" href="contact.html">Request Consultation</a>
            </section>
            <section>
                <h2>Core Services</h2>
                <div class="grid">{service_cards}</div>
            </section>
        """,
        "about": f"""
            <section>
                <h1>About {company_name}</h1>
                <p>{company_name} supports clients with practical delivery plans and predictable execution.</p>
                <p>Our team blends engineering, operations, and advisory expertise to keep outcomes focused and measurable.</p>
            </section>
        """,
        "services": f"""
            <section>
                <h1>Services</h1>
                <div class="grid">{service_cards}</div>
            </section>
        """,
        "blog": f"""
            <section>
                <h1>Latest Insights</h1>
                <div class="grid">{blog_cards}</div>
            </section>
        """,
        "contact": f"""
            <section>
                <h1>Contact</h1>
                <p>Email: <a href="mailto:hello@{domain}">hello@{domain}</a></p>
                <p>Primary contact: {profile["contact_role"]}</p>
                <form class="contact-form" action="#" method="post">
                    <label>Name</label>
                    <input type="text" placeholder="Your name" />
                    <label>Email</label>
                    <input type="email" placeholder="you@company.com" />
                    <label>Message</label>
                    <textarea rows="5" placeholder="How can we help?"></textarea>
                    <button type="submit">Send Message</button>
                </form>
            </section>
        """,
        "privacy": f"""
            <section>
                <h1>Privacy Policy</h1>
                <p>{company_name} values user privacy and limits data collection to what is required for service delivery.</p>
                <p>For data requests or removal questions, contact <a href="mailto:privacy@{domain}">privacy@{domain}</a>.</p>
            </section>
        """,
    }
    body = sections.get(page, sections["index"])

    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="{company_name} - {profile["summary"]}" />
    <title>{company_name} | {page_titles.get(page, "Home")}</title>
    <link rel="stylesheet" href="css/style.css" />
    <script defer src="js/main.js"></script>
</head>
<body>
    <header class="site-header">
        <div class="container header-inner">
            <a class="brand" href="index.html">{company_name}</a>
            <button class="menu-toggle" aria-label="Toggle menu">Menu</button>
            <nav class="site-nav">{nav_html}</nav>
        </div>
    </header>
    <main class="container">
        {body}
    </main>
    <footer class="site-footer">
        <div class="container">
            <p>&copy; <span id="year"></span> {company_name}. All rights reserved.</p>
            <p class="muted">{domain}</p>
        </div>
    </footer>
</body>
</html>
"""


def build_default_css(category):
    palette = {
        "technology": ("#0b1f3a", "#1d4ed8", "#0ea5e9"),
        "consulting": ("#1f2937", "#3b82f6", "#14b8a6"),
        "finance": ("#10221b", "#2f855a", "#84cc16"),
        "healthcare": ("#1f2937", "#059669", "#06b6d4"),
        "education": ("#1f2937", "#7c3aed", "#22d3ee"),
        "news": ("#111827", "#dc2626", "#f59e0b"),
        "marketing": ("#111827", "#ec4899", "#f97316"),
        "ecommerce": ("#111827", "#0f766e", "#84cc16"),
        "travel": ("#082f49", "#0ea5e9", "#14b8a6"),
    }
    dark, primary, accent = palette.get(category, palette["technology"])
    return f"""* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
    color: #111827;
    background: #f8fafc;
}}

.container {{
    width: min(1040px, 92vw);
    margin: 0 auto;
}}

.site-header {{
    background: linear-gradient(120deg, {dark}, {primary});
    color: #ffffff;
}}

.header-inner {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 1rem 0;
}}

.brand {{
    color: #ffffff;
    text-decoration: none;
    font-weight: 700;
    letter-spacing: 0.02em;
}}

.site-nav {{
    display: flex;
    gap: 0.5rem;
}}

.site-nav a {{
    color: #ffffff;
    opacity: 0.9;
    text-decoration: none;
    padding: 0.4rem 0.7rem;
    border-radius: 999px;
}}

.site-nav a.active,
.site-nav a:hover {{
    opacity: 1;
    background: rgba(255, 255, 255, 0.18);
}}

.menu-toggle {{
    display: none;
}}

main {{
    padding: 2rem 0 3rem;
}}

h1, h2, h3 {{
    line-height: 1.2;
}}

.hero {{
    padding: 2.5rem 1.25rem;
    background: linear-gradient(150deg, #ffffff, #ecfeff);
    border: 1px solid #dbeafe;
    border-radius: 16px;
}}

.hero h1 {{
    margin-top: 0;
    margin-bottom: 0.5rem;
}}

.btn {{
    display: inline-block;
    margin-top: 0.75rem;
    padding: 0.7rem 1rem;
    border-radius: 10px;
    background: {primary};
    color: #ffffff;
    text-decoration: none;
}}

.grid {{
    margin-top: 1rem;
    display: grid;
    gap: 1rem;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
}}

.card {{
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 14px;
    padding: 1rem;
    box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
}}

.contact-form {{
    margin-top: 1rem;
    display: grid;
    gap: 0.45rem;
}}

.contact-form input,
.contact-form textarea {{
    width: 100%;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 0.6rem 0.7rem;
    font: inherit;
}}

.contact-form button {{
    margin-top: 0.5rem;
    padding: 0.65rem 1rem;
    border: 0;
    border-radius: 8px;
    background: {accent};
    color: #ffffff;
    cursor: pointer;
}}

.site-footer {{
    padding: 1.5rem 0 2.5rem;
    border-top: 1px solid #e5e7eb;
    color: #4b5563;
    background: #ffffff;
}}

.muted {{
    color: #6b7280;
}}

@media (max-width: 760px) {{
    .menu-toggle {{
        display: inline-block;
        background: rgba(255, 255, 255, 0.2);
        border: 1px solid rgba(255, 255, 255, 0.35);
        color: #ffffff;
        border-radius: 7px;
        padding: 0.4rem 0.6rem;
    }}
    .site-nav {{
        display: none;
        position: absolute;
        top: 62px;
        right: 4vw;
        flex-direction: column;
        background: {dark};
        border-radius: 10px;
        padding: 0.4rem;
    }}
    .site-nav.open {{
        display: flex;
    }}
}}
"""


def build_default_js():
    return """(function () {
    var nav = document.querySelector('.site-nav');
    var toggle = document.querySelector('.menu-toggle');
    if (toggle && nav) {
        toggle.addEventListener('click', function () {
            nav.classList.toggle('open');
        });
    }
    var year = document.getElementById('year');
    if (year) {
        year.textContent = new Date().getFullYear();
    }
})();"""


def ensure_site_files(site_dir, category, company_name, domain):
    (site_dir / "css").mkdir(parents=True, exist_ok=True)
    (site_dir / "js").mkdir(parents=True, exist_ok=True)

    for page in SITE_PAGES:
        fpath = site_dir / ("index.html" if page == "index" else f"{page}.html")
        if not fpath.exists() or fpath.stat().st_size < 120:
            fpath.write_text(build_default_html(page, category, company_name, domain), encoding="utf-8")

    css_path = site_dir / "css" / "style.css"
    if not css_path.exists() or css_path.stat().st_size < 200:
        css_path.write_text(build_default_css(category), encoding="utf-8")

    js_path = site_dir / "js" / "main.js"
    if not js_path.exists() or js_path.stat().st_size < 50:
        js_path.write_text(build_default_js(), encoding="utf-8")




def generate_site(domain, category, company_name):
    """Generate site files locally in output/<domain>/. Returns the output path."""
    template_src = TEMPLATES_DIR / category
    site_dir = OUTPUT_DIR / domain.replace(".", "-")

    if site_dir.exists():
        shutil.rmtree(site_dir)
    site_dir.mkdir(parents=True, exist_ok=True)

    if template_src.is_dir():
        shutil.copytree(template_src, site_dir, dirs_exist_ok=True)

    # If template files are missing/corrupt, synthesize a complete baseline site.
    ensure_site_files(site_dir, category, company_name, domain)

    for fpath in site_dir.rglob("*"):
        if fpath.is_file() and fpath.suffix in (".html", ".css", ".js", ".json", ".txt"):
            try:
                content = fpath.read_text(encoding="utf-8")
                content = content.replace("{{COMPANY_NAME}}", company_name)
                content = content.replace("{{DOMAIN}}", domain)
                fpath.write_text(content, encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                pass

    (site_dir / "CNAME").write_text(domain + "\n", encoding="utf-8")

    return site_dir


# ── Email provider helpers ──────────────────────────────────────


MAILJET_SENDER_CACHE_TTL_SECONDS = 300
MAILJET_SENDER_CACHE = {"by_email": {}, "by_domain": {}}


def _extract_email_domain(address):
    value = str(address or "").strip().lower()
    if "@" not in value:
        return "", ""
    local, domain = value.rsplit("@", 1)
    return local.strip(), domain.strip()


def _smtp2go_api_request(path, payload=None, timeout=20):
    cfg = load_config()
    api_key = str(cfg.get("smtp2go_api_key") or "").strip()
    if not api_key:
        return {"success": False, "error": "SMTP2GO not configured", "status_code": None, "json": {}}

    url = f"{SMTP2GO_API_BASE.rstrip('/')}/{str(path or '').lstrip('/')}"
    headers = {
        "X-Smtp2go-Api-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        resp = requests.post(url, headers=headers, json=payload or {}, timeout=timeout)
    except Exception as exc:
        return {"success": False, "error": str(exc), "status_code": None, "json": {}}

    try:
        body = resp.json()
    except Exception:
        body = {}

    ok_http = 200 <= int(resp.status_code or 0) < 300
    err = None
    if not ok_http:
        err = f"HTTP {resp.status_code}"
    elif isinstance(body, dict):
        data_block = body.get("data") if isinstance(body.get("data"), dict) else {}
        if data_block:
            failed_count = _safe_int(data_block.get("failed"), 0) or 0
            if failed_count > 0:
                err_detail = data_block.get("error") or data_block.get("errors") or body.get("error")
                err = str(err_detail or "SMTP2GO reported failed recipients")
        top_error = body.get("error")
        if top_error and not err:
            err = str(top_error)

    return {
        "success": ok_http and not err,
        "error": err,
        "status_code": resp.status_code,
        "json": body if isinstance(body, dict) else {},
    }


def _mailjet_api_get(resource, params=None, timeout=20):
    cfg = load_config()
    api_key = str(cfg.get("mailjet_api_key") or "").strip()
    api_secret = str(cfg.get("mailjet_api_secret") or "").strip()
    if not api_key or not api_secret:
        return {"success": False, "error": "Mailjet not configured", "status_code": None, "data": []}
    try:
        resp = requests.get(
            f"https://api.mailjet.com/v3/REST/{resource}",
            auth=(api_key, api_secret),
            params=params or {},
            timeout=timeout,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc), "status_code": None, "data": []}
    if resp.status_code != 200:
        return {"success": False, "error": f"HTTP {resp.status_code}", "status_code": resp.status_code, "data": []}
    try:
        payload = resp.json()
    except Exception:
        return {"success": False, "error": "Invalid Mailjet response", "status_code": resp.status_code, "data": []}
    return {
        "success": True,
        "status_code": resp.status_code,
        "data": payload.get("Data") or [],
        "count": payload.get("Count"),
        "total": payload.get("Total"),
    }


def _get_mailjet_sender_records(email):
    normalized = str(email or "").strip().lower()
    if not normalized:
        return []
    cache_entry = MAILJET_SENDER_CACHE["by_email"].get(normalized)
    if cache_entry and (time.time() - cache_entry.get("ts", 0) < MAILJET_SENDER_CACHE_TTL_SECONDS):
        return cache_entry.get("rows", [])
    result = _mailjet_api_get("sender", {"Email": normalized})
    rows = result.get("data", []) if result.get("success") else []
    MAILJET_SENDER_CACHE["by_email"][normalized] = {"ts": time.time(), "rows": rows}
    return rows


def _get_mailjet_domain_sender_records(domain):
    normalized = str(domain or "").strip().lower()
    if not normalized:
        return []
    cache_entry = MAILJET_SENDER_CACHE["by_domain"].get(normalized)
    if cache_entry and (time.time() - cache_entry.get("ts", 0) < MAILJET_SENDER_CACHE_TTL_SECONDS):
        return cache_entry.get("rows", [])
    wildcard = f"*@{normalized}"
    result = _mailjet_api_get("sender", {"Email": wildcard})
    rows = result.get("data", []) if result.get("success") else []
    MAILJET_SENDER_CACHE["by_domain"][normalized] = {"ts": time.time(), "rows": rows}
    return rows


def validate_mailjet_sender(from_email):
    email = str(from_email or "").strip().lower()
    local, domain = _extract_email_domain(email)
    if not local or not domain:
        return {"valid": False, "error": "Invalid From Email address format."}

    exact_rows = _get_mailjet_sender_records(email)
    wildcard_rows = _get_mailjet_domain_sender_records(domain)

    def _active(rows, match_email=None):
        for row in rows or []:
            row_email = str(row.get("Email") or "").strip().lower()
            status = str(row.get("Status") or "").strip().lower()
            if match_email and row_email != match_email:
                continue
            if status == "active":
                return row
        return None

    active_exact = _active(exact_rows, email)
    active_wildcard = _active(wildcard_rows)
    exact_inactive = None
    for row in exact_rows or []:
        row_email = str(row.get("Email") or "").strip().lower()
        if row_email == email and str(row.get("Status") or "").strip().lower() != "active":
            exact_inactive = row
            break

    if active_exact or active_wildcard:
        return {
            "valid": True,
            "email": email,
            "domain": domain,
            "sender_mode": "exact" if active_exact else "domain_wildcard",
            "sender_status": "active",
            "warning": (
                "Exact sender is inactive, but domain wildcard sender is active."
                if (not active_exact and exact_inactive and active_wildcard)
                else ""
            ),
        }

    if exact_inactive:
        return {
            "valid": False,
            "email": email,
            "domain": domain,
            "error": (
                f"Mailjet sender {email} exists but is not active (Status: {exact_inactive.get('Status')}). "
                "Activate/verify the sender or use a domain with an active Mailjet sender."
            ),
        }

    if exact_rows or wildcard_rows:
        return {
            "valid": False,
            "email": email,
            "domain": domain,
            "error": (
                f"Mailjet sender/domain for {email} is not active in this tenant. "
                "Add and verify the sender or authenticated sending domain in Mailjet first."
            ),
        }

    return {
        "valid": False,
        "email": email,
        "domain": domain,
        "error": (
            f"{domain} is not configured in this Mailjet tenant (no active sender record found for {email} or *@{domain})."
        ),
    }


def get_mailjet_client():
    cfg = load_config()
    api_key = cfg.get("mailjet_api_key", "")
    api_secret = cfg.get("mailjet_api_secret", "")
    if not api_key or not api_secret:
        return None
    try:
        from mailjet_rest import Client
        return Client(auth=(api_key, api_secret), version="v3.1")
    except Exception:
        return None


def send_warmup_email_mailjet(from_email, from_name, to_email, subject, body):
    client = get_mailjet_client()
    if not client:
        return {"success": False, "error": "Mailjet not configured", "provider": "mailjet"}
    sender_check = validate_mailjet_sender(from_email)
    if not sender_check.get("valid"):
        return {
            "success": False,
            "error": sender_check.get("error", "From Email is not authorized in Mailjet"),
            "provider": "mailjet",
        }
    data = {
        "Messages": [{
            "From": {"Email": from_email, "Name": from_name},
            "To": [{"Email": to_email, "Name": ""}],
            "Subject": subject,
            "TextPart": body,
            "HTMLPart": f"<p>{body}</p>",
        }]
    }
    try:
        result = client.send.create(data=data)
        status_code = int(getattr(result, "status_code", 0) or 0)
        try:
            payload = result.json()
        except Exception:
            payload = {}
        meta = _extract_mailjet_send_meta({"data": payload})
        mailjet_status = _normalize_mail_status(meta.get("mailjet_status"))
        accepted_http = status_code in (200, 201)
        accepted_by_mailjet = mailjet_status in {"success", "accepted", "queued"} or (
            accepted_http and mailjet_status == "unknown"
        )
        success = accepted_http and accepted_by_mailjet

        error_parts = []
        if not accepted_http:
            error_parts.append(f"HTTP {status_code}")
        elif mailjet_status not in {"success", "accepted", "queued", "unknown"}:
            error_parts.append(f"Mailjet status: {mailjet_status}")

        mailjet_error = _format_mailjet_errors(meta.get("mailjet_error"))
        if mailjet_error:
            error_parts.append(mailjet_error)

        initial_delivery_status = _initial_mail_delivery_status(mailjet_status, success)
        response = {
            "success": success,
            "status": status_code,
            "data": payload,
            "provider": "mailjet",
            "provider_status": mailjet_status,
            "mailjet_status": mailjet_status,
            "delivery_status": initial_delivery_status,
            "message_id": meta.get("message_id"),
            "message_uuid": meta.get("message_uuid"),
            "sender_validation": sender_check,
        }
        if error_parts:
            response["error"] = " | ".join([part for part in error_parts if part])
        return response
    except Exception as e:
        return {"success": False, "error": str(e), "provider": "mailjet"}


def send_warmup_email_smtp2go(from_email, from_name, to_email, subject, body):
    sender_value = str(from_email or "").strip()
    if from_name:
        sender_value = f"{str(from_name).strip()} <{sender_value}>"
    resp = _smtp2go_api_request(
        "email/send",
        payload={
            "sender": sender_value,
            "to": [str(to_email or "").strip()],
            "subject": str(subject or ""),
            "text_body": str(body or ""),
            "html_body": f"<p>{str(body or '')}</p>",
        },
        timeout=30,
    )
    payload = resp.get("json") if isinstance(resp.get("json"), dict) else {}
    data_block = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    ok = bool(resp.get("success"))
    failed_count = _safe_int(data_block.get("failed"), 0) or 0
    success_count = _safe_int(data_block.get("succeeded"), 0)
    if success_count is not None and success_count <= 0 and failed_count > 0:
        ok = False
    provider_status = "accepted" if ok else "failed"

    # SMTP2GO may return request/message IDs under different keys depending on account/features.
    message_id = (
        data_block.get("email_id")
        or data_block.get("message_id")
        or payload.get("request_id")
        or payload.get("id")
    )
    response = {
        "success": ok,
        "status": resp.get("status_code"),
        "data": payload,
        "provider": "smtp2go",
        "provider_status": provider_status,
        "delivery_status": "accepted" if ok else "failed",
        "message_id": str(message_id) if message_id else None,
    }
    if not ok:
        error_parts = []
        if resp.get("error"):
            error_parts.append(str(resp.get("error")))
        detail = data_block.get("errors") or data_block.get("error")
        if detail:
            error_parts.append(str(detail))
        response["error"] = " | ".join([p for p in error_parts if p]) or "SMTP2GO send failed"
    return response


def send_warmup_email(from_email, from_name, to_email, subject, body):
    cfg = load_config()
    provider = get_email_provider(cfg)
    if provider == "smtp2go":
        return send_warmup_email_smtp2go(from_email, from_name, to_email, subject, body)
    return send_warmup_email_mailjet(from_email, from_name, to_email, subject, body)


NEGATIVE_MAIL_STATUSES = {"bounce", "bounced", "blocked", "spam", "unsub", "deferred", "hard_bounce", "soft_bounce"}


def _normalize_mail_status(value):
    status = str(value or "").strip().lower().replace(" ", "_")
    if not status:
        return "unknown"
    aliases = {
        "softbounced": "soft_bounce",
        "hardbounced": "hard_bounce",
        "unsubscribed": "unsub",
    }
    return aliases.get(status, status)


def _format_mailjet_errors(errors):
    if not errors:
        return ""
    if isinstance(errors, list):
        parts = []
        for item in errors:
            if isinstance(item, dict):
                code = item.get("ErrorIdentifier") or item.get("ErrorCode") or item.get("Code")
                msg = item.get("ErrorMessage") or item.get("Message")
                if code and msg:
                    parts.append(f"{code}: {msg}")
                elif msg:
                    parts.append(str(msg))
                elif code:
                    parts.append(str(code))
                else:
                    parts.append(json.dumps(item, sort_keys=True))
            else:
                parts.append(str(item))
        return "; ".join([p for p in parts if p])
    if isinstance(errors, dict):
        return json.dumps(errors, sort_keys=True)
    return str(errors)


def _initial_mail_delivery_status(mailjet_status, success):
    status = _normalize_mail_status(mailjet_status)
    if not success:
        return "failed"
    if status in {"unknown", "success"}:
        return "accepted"
    return status


def _delivery_status_counts_as_success(value):
    status = _normalize_mail_status(value)
    if status in NEGATIVE_MAIL_STATUSES or status in {"failed", "error", "rejected", "unknown"}:
        return False
    return status in {"accepted", "queued", "sent", "success", "delivered", "opened", "clicked"}


def _safe_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _mailjet_status_priority(value):
    status = _normalize_mail_status(value)
    priority = {
        "failed": 100,
        "error": 100,
        "rejected": 95,
        "hard_bounce": 90,
        "soft_bounce": 89,
        "bounce": 88,
        "bounced": 88,
        "blocked": 87,
        "spam": 86,
        "unsub": 85,
        "deferred": 60,
        "clicked": 50,
        "opened": 45,
        "delivered": 40,
        "sent": 35,
        "queued": 20,
        "accepted": 15,
        "success": 15,
        "unknown": 0,
    }
    return priority.get(status, 10)


def _derive_status_from_messageinformation(info_row):
    if not info_row:
        return None

    # Mailjet's messageinformation payload can expose lifecycle counts. Some transactional
    # accounts return "SentCount" as a UNIX timestamp-like integer instead of a counter.
    negative_mappings = [
        ("HardBouncedCount", "hard_bounce"),
        ("SoftBouncedCount", "soft_bounce"),
        ("BounceCount", "bounced"),
        ("BouncedCount", "bounced"),
        ("BlockedCount", "blocked"),
        ("SpamCount", "spam"),
        ("UnsubCount", "unsub"),
        ("UnsubscribedCount", "unsub"),
        ("DeferredCount", "deferred"),
    ]
    for key, status in negative_mappings:
        value = _safe_int(info_row.get(key))
        if value and value > 0:
            return status

    if (_safe_int(info_row.get("ClickTrackedCount")) or 0) > 0:
        return "clicked"
    if (_safe_int(info_row.get("OpenTrackedCount")) or 0) > 0:
        return "opened"

    sent_value = _safe_int(info_row.get("SentCount"))
    if sent_value and sent_value > 0:
        return "sent"

    if (_safe_int(info_row.get("QueuedCount")) or 0) > 0:
        return "queued"
    return None


def _choose_mailjet_delivery_status(*candidates):
    chosen = "unknown"
    chosen_priority = -1
    for candidate in candidates:
        status = _normalize_mail_status(candidate)
        pri = _mailjet_status_priority(status)
        if pri > chosen_priority:
            chosen = status
            chosen_priority = pri
    return chosen


def _fetch_mailjet_message_information(limit=200):
    cfg = load_config()
    api_key = cfg.get("mailjet_api_key", "")
    api_secret = cfg.get("mailjet_api_secret", "")
    if not api_key or not api_secret:
        return {"success": False, "error": "Mailjet not configured", "rows": []}

    try:
        resp = requests.get(
            "https://api.mailjet.com/v3/REST/messageinformation",
            auth=(api_key, api_secret),
            params={
                "Limit": max(1, min(int(limit), 500)),
            },
            timeout=20,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc), "rows": []}

    if resp.status_code != 200:
        return {"success": False, "error": f"HTTP {resp.status_code}", "rows": []}

    try:
        payload = resp.json()
    except Exception:
        return {"success": False, "error": "Invalid Mailjet response", "rows": []}

    rows = payload.get("Data") or []
    return {"success": True, "rows": rows}


def _fetch_mailjet_message_row_by_id(message_id):
    cfg = load_config()
    api_key = cfg.get("mailjet_api_key", "")
    api_secret = cfg.get("mailjet_api_secret", "")
    if not api_key or not api_secret:
        return {"success": False, "error": "Mailjet not configured", "row": None}
    try:
        resp = requests.get(
            f"https://api.mailjet.com/v3/REST/message/{message_id}",
            auth=(api_key, api_secret),
            timeout=20,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc), "row": None}
    if resp.status_code == 404:
        return {"success": True, "row": None}
    if resp.status_code != 200:
        return {"success": False, "error": f"HTTP {resp.status_code}", "row": None}
    try:
        row = (resp.json().get("Data") or [None])[0]
    except Exception:
        return {"success": False, "error": "Invalid Mailjet response", "row": None}
    return {"success": True, "row": row}


def _fetch_mailjet_message_information_row_by_id(message_id):
    cfg = load_config()
    api_key = cfg.get("mailjet_api_key", "")
    api_secret = cfg.get("mailjet_api_secret", "")
    if not api_key or not api_secret:
        return {"success": False, "error": "Mailjet not configured", "row": None}
    try:
        resp = requests.get(
            f"https://api.mailjet.com/v3/REST/messageinformation/{message_id}",
            auth=(api_key, api_secret),
            timeout=20,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc), "row": None}
    if resp.status_code == 404:
        return {"success": True, "row": None}
    if resp.status_code != 200:
        return {"success": False, "error": f"HTTP {resp.status_code}", "row": None}
    try:
        row = (resp.json().get("Data") or [None])[0]
    except Exception:
        return {"success": False, "error": "Invalid Mailjet response", "row": None}
    return {"success": True, "row": row}


def _fetch_mailjet_contact_row_by_id(contact_id):
    cfg = load_config()
    api_key = cfg.get("mailjet_api_key", "")
    api_secret = cfg.get("mailjet_api_secret", "")
    if not api_key or not api_secret:
        return {"success": False, "error": "Mailjet not configured", "row": None}
    try:
        resp = requests.get(
            f"https://api.mailjet.com/v3/REST/contact/{contact_id}",
            auth=(api_key, api_secret),
            timeout=20,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc), "row": None}
    if resp.status_code == 404:
        return {"success": True, "row": None}
    if resp.status_code != 200:
        return {"success": False, "error": f"HTTP {resp.status_code}", "row": None}
    try:
        row = (resp.json().get("Data") or [None])[0]
    except Exception:
        return {"success": False, "error": "Invalid Mailjet response", "row": None}
    return {"success": True, "row": row}


def _fetch_mailjet_sender_row_by_id(sender_id):
    cfg = load_config()
    api_key = cfg.get("mailjet_api_key", "")
    api_secret = cfg.get("mailjet_api_secret", "")
    if not api_key or not api_secret:
        return {"success": False, "error": "Mailjet not configured", "row": None}
    try:
        resp = requests.get(
            f"https://api.mailjet.com/v3/REST/sender/{sender_id}",
            auth=(api_key, api_secret),
            timeout=20,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc), "row": None}
    if resp.status_code == 404:
        return {"success": True, "row": None}
    if resp.status_code != 200:
        return {"success": False, "error": f"HTTP {resp.status_code}", "row": None}
    try:
        row = (resp.json().get("Data") or [None])[0]
    except Exception:
        return {"success": False, "error": "Invalid Mailjet response", "row": None}
    return {"success": True, "row": row}


def _normalize_mailjet_message_record(message_row=None, info_row=None):
    message_status = _normalize_mail_status((message_row or {}).get("Status") or (message_row or {}).get("State"))
    info_status = _derive_status_from_messageinformation(info_row)
    status = _choose_mailjet_delivery_status(message_status, info_status)
    row_id = (message_row or {}).get("ID") or (info_row or {}).get("ID")
    return {
        "message_id": (message_row or {}).get("MessageID") or row_id,
        "message_resource_id": row_id,
        "message_uuid": (message_row or {}).get("MessageUUID") or (message_row or {}).get("UUID"),
        "to": (
            (message_row or {}).get("ToEmail")
            or (message_row or {}).get("To")
            or (message_row or {}).get("Recipient")
            or (message_row or {}).get("ContactAlt")
            or (info_row or {}).get("ToEmail")
            or (info_row or {}).get("To")
            or (info_row or {}).get("Recipient")
            or ""
        ),
        "from": (
            (message_row or {}).get("FromEmail")
            or (message_row or {}).get("From")
            or (info_row or {}).get("FromEmail")
            or (info_row or {}).get("From")
            or ""
        ),
        "subject": (message_row or {}).get("Subject") or (info_row or {}).get("Subject") or "",
        "contact_id": (message_row or {}).get("ContactID") or (info_row or {}).get("ContactID"),
        "sender_id": (message_row or {}).get("SenderID") or (info_row or {}).get("SenderID"),
        "delivery_status": status,
        "last_event_at": (
            (info_row or {}).get("SendEndAt")
            or (info_row or {}).get("CreatedAt")
            or (message_row or {}).get("ArrivedAt")
            or (message_row or {}).get("LastActivityAt")
            or (message_row or {}).get("CreatedAt")
        ),
        "raw_state": (message_row or {}).get("State"),
        "raw_message_status": message_status,
        "mailjet_info_status": info_status,
    }


def _fetch_mailjet_message_status_for_id(message_id):
    msg_resp = _fetch_mailjet_message_row_by_id(message_id)
    if not msg_resp.get("success"):
        return {"success": False, "error": msg_resp.get("error")}
    info_resp = _fetch_mailjet_message_information_row_by_id(message_id)
    if not info_resp.get("success"):
        return {"success": False, "error": info_resp.get("error")}
    message_row = msg_resp.get("row")
    info_row = info_resp.get("row")
    if not message_row and not info_row:
        return {"success": True, "entry": None}
    return {"success": True, "entry": _normalize_mailjet_message_record(message_row, info_row)}


def _extract_mailjet_send_meta(result):
    payload = result.get("data") or {}
    messages = payload.get("Messages") or []
    if not messages:
        return {}
    first = messages[0] or {}
    to_list = first.get("To") or []
    first_to = to_list[0] if to_list else {}
    return {
        "message_id": first_to.get("MessageID") or first.get("MessageID"),
        "message_uuid": first_to.get("MessageUUID") or first.get("MessageUUID"),
        "mailjet_status": _normalize_mail_status(first.get("Status")),
        "mailjet_error": first.get("Errors"),
    }


def append_warmup_log_entry(entry, limit=800):
    payload = load_email_log()
    entries = payload.get("entries", [])
    entries.append(entry)
    if len(entries) > limit:
        del entries[:-limit]
    payload["entries"] = entries
    save_email_log(payload)


def summarize_warmup_entries(entries):
    summary = {
        "total": len(entries),
        "sent_ok": 0,
        "send_failed": 0,
        "negative_events": 0,
        "status_breakdown": {},
    }
    for item in entries:
        if item.get("success"):
            summary["sent_ok"] += 1
        else:
            summary["send_failed"] += 1
        status = _normalize_mail_status(item.get("delivery_status") or item.get("mailjet_status") or "unknown")
        summary["status_breakdown"][status] = summary["status_breakdown"].get(status, 0) + 1
        if status in NEGATIVE_MAIL_STATUSES:
            summary["negative_events"] += 1
    return summary


def summarize_mailjet_entries(entries):
    rows = list(entries or [])
    summary = {
        "total": len(rows),
        "sent_ok": 0,
        "send_failed": 0,
        "negative_events": 0,
        "status_breakdown": {},
    }
    for item in rows:
        status = _normalize_mail_status(item.get("delivery_status") or item.get("mailjet_status") or "unknown")
        summary["status_breakdown"][status] = summary["status_breakdown"].get(status, 0) + 1
        ok = _delivery_status_counts_as_success(status)
        if ok:
            summary["sent_ok"] += 1
        else:
            summary["send_failed"] += 1
        if status in NEGATIVE_MAIL_STATUSES:
            summary["negative_events"] += 1
    return summary


def _paginate_warmup_entries(entries, page=1, per_page=WARMUP_LOG_PAGE_SIZE):
    rows = _sorted_warmup_entries(entries)
    try:
        page_num = max(1, int(page))
    except (TypeError, ValueError):
        page_num = 1
    try:
        per_page_num = int(per_page)
    except (TypeError, ValueError):
        per_page_num = WARMUP_LOG_PAGE_SIZE
    per_page_num = max(1, min(per_page_num, WARMUP_LOG_PAGE_SIZE))
    total_entries = len(rows)
    total_pages = max(1, (total_entries + per_page_num - 1) // per_page_num)
    if page_num > total_pages:
        page_num = total_pages
    start = (page_num - 1) * per_page_num
    end = start + per_page_num
    page_rows = rows[start:end]
    return {
        "entries": page_rows,
        "page": page_num,
        "per_page": per_page_num,
        "total_entries": total_entries,
        "total_pages": total_pages,
        "has_prev": page_num > 1,
        "has_next": page_num < total_pages,
    }


def _filter_warmup_entries(entries, domain_filter=""):
    domain_filter = str(domain_filter or "").strip().lower()
    if not domain_filter:
        return list(entries or [])
    filtered = []
    for row in entries or []:
        from_email = row.get("from_email") or ""
        _, from_domain = _extract_email_domain(from_email)
        scheduled_domain = str(row.get("scheduled_domain") or "").strip().lower()
        if from_domain == domain_filter or scheduled_domain == domain_filter:
            filtered.append(row)
    return filtered


def _is_blank_mailjet_poll_entry(row):
    if str(row.get("source") or "") != "mailjet_poll":
        return False
    return not any([
        str(row.get("from_email") or "").strip(),
        str(row.get("to") or "").strip(),
        str(row.get("subject") or "").strip(),
        str(row.get("error") or "").strip(),
    ])


def _prune_blank_mailjet_poll_entries(entries):
    if not entries:
        return []
    pruned = []
    removed = 0
    for row in entries:
        if _is_blank_mailjet_poll_entry(row):
            removed += 1
            continue
        pruned.append(row)
    return pruned


def _mailjet_email_looks_anonymized(value):
    email = str(value or "").strip().lower()
    if not email:
        return False
    if email.startswith("*@"):
        return True
    if email.endswith("@domain.invalid"):
        return True
    return False


def _mailjet_subject_looks_placeholder(value):
    subject = str(value or "").strip()
    if not subject:
        return False
    return re.match(r"^Mailjet Message \d+$", subject) is not None


def _append_mailjet_import_note(existing_note, note):
    current = str(existing_note or "").strip()
    add = str(note or "").strip()
    if not add:
        return current
    if not current:
        return add
    if add in current:
        return current
    return f"{current}; {add}"


def _sanitize_mailjet_import_fields(from_value, to_value, subject_value):
    clean_from = str(from_value or "").strip()
    clean_to = str(to_value or "").strip()
    clean_subject = str(subject_value or "").strip()
    notes = []

    if _mailjet_email_looks_anonymized(clean_from):
        clean_from = ""
        notes.append("Sender masked by Mailjet API")
    if _mailjet_email_looks_anonymized(clean_to):
        clean_to = ""
        notes.append("Recipient masked by Mailjet API")
    if _mailjet_subject_looks_placeholder(clean_subject):
        clean_subject = ""
    if not clean_subject:
        notes.append("Subject unavailable from Mailjet history API")

    deduped_notes = []
    for note in notes:
        if note not in deduped_notes:
            deduped_notes.append(note)
    return clean_from, clean_to, clean_subject, "; ".join(deduped_notes)


def _sanitize_mailjet_poll_log_entry(row):
    if str((row or {}).get("source") or "") != "mailjet_poll":
        return False
    changed = False
    clean_from, clean_to, clean_subject, note = _sanitize_mailjet_import_fields(
        row.get("from_email"),
        row.get("to"),
        row.get("subject"),
    )
    if str(row.get("from_email") or "") != clean_from:
        row["from_email"] = clean_from
        changed = True
    if str(row.get("to") or "") != clean_to:
        row["to"] = clean_to
        changed = True
    if str(row.get("subject") or "") != clean_subject:
        row["subject"] = clean_subject
        changed = True
    new_note = _append_mailjet_import_note(row.get("error"), note)
    if str(row.get("error") or "") != new_note:
        row["error"] = new_note
        changed = True
    return changed


def _warmup_log_note_meta(row):
    source = str((row or {}).get("source") or "").strip()
    error_text = str((row or {}).get("error") or "").strip()
    parts = [p.strip() for p in error_text.split(";") if p and p.strip()]

    badges = []
    detail_parts = []

    if source == "mailjet_poll":
        badges.append({"label": "Mailjet Import", "tone": "info"})

    known_map = {
        "Sender masked by Mailjet API": ("Sender Hidden", "muted"),
        "Recipient masked by Mailjet API": ("Recipient Hidden", "muted"),
        "Subject unavailable from Mailjet history API": ("No Subject", "muted"),
    }
    seen_badges = set()
    for part in parts:
        mapped = known_map.get(part)
        if mapped:
            label, tone = mapped
            key = (label, tone)
            if key not in seen_badges:
                badges.append({"label": label, "tone": tone})
                seen_badges.add(key)
            continue
        detail_parts.append(part)

    if not badges and not detail_parts and source == "mailjet_poll":
        badges.append({"label": "Mailjet Import", "tone": "info"})

    return {
        "badges": badges,
        "detail": "; ".join(detail_parts).strip(),
    }


def _decorate_warmup_log_entries_for_ui(entries):
    decorated = []
    for row in entries or []:
        out = dict(row or {})
        notes = _warmup_log_note_meta(out)
        out["note_badges"] = notes.get("badges", [])
        out["note_detail"] = notes.get("detail", "")
        decorated.append(out)
    return decorated


def _warmup_log_response(domain_filter="", page=1, per_page=WARMUP_LOG_PAGE_SIZE):
    payload = load_email_log()
    all_entries_raw = _sorted_warmup_entries(_prune_blank_mailjet_poll_entries(payload.get("entries", [])))
    # History imported from Mailjet lacks reliable metadata in many tenants (masked recipients / no subject).
    # Keep the visible log focused on Warden-originated sends while Mailjet sync contributes summary metrics.
    all_entries = [row for row in all_entries_raw if str((row or {}).get("source") or "") != "mailjet_poll"]
    filtered_entries = _filter_warmup_entries(all_entries, domain_filter=domain_filter)
    paged = _paginate_warmup_entries(filtered_entries, page=page, per_page=per_page)
    paged["entries"] = _decorate_warmup_log_entries_for_ui(paged.get("entries", []))
    mailjet_summary = payload.get("mailjet_sync_summary") if isinstance(payload.get("mailjet_sync_summary"), dict) else None
    if get_email_provider() != "mailjet":
        mailjet_summary = None
    display_summary = mailjet_summary or summarize_warmup_entries(filtered_entries)
    summary_label = None
    if mailjet_summary:
        summary_label = f"Mailjet Sync Summary ({payload.get('mailjet_sync_label') or 'Custom Window'})"
    else:
        summary_label = "Warmup Log Summary (visible entries)"
    return {
        **paged,
        "summary": display_summary,
        "summary_all": summarize_warmup_entries(all_entries),
        "summary_log": summarize_warmup_entries(filtered_entries),
        "summary_label": summary_label,
        "mailjet_sync_summary": mailjet_summary,
        "mailjet_sync_lookback": payload.get("mailjet_sync_lookback"),
        "mailjet_sync_label": payload.get("mailjet_sync_label"),
        "last_synced_at": payload.get("last_synced_at"),
        "domain_filter": str(domain_filter or "").strip().lower() or None,
    }


def fetch_mailjet_recent_messages(limit=200, lookback=None):
    cfg = load_config()
    api_key = cfg.get("mailjet_api_key", "")
    api_secret = cfg.get("mailjet_api_secret", "")
    if not api_key or not api_secret:
        return {"success": False, "error": "Mailjet not configured", "entries": []}
    lookback_key = normalize_mailjet_sync_lookback(lookback)
    cutoff_dt = mailjet_sync_lookback_cutoff(lookback_key)

    try:
        resp = requests.get(
            "https://api.mailjet.com/v3/REST/message",
            auth=(api_key, api_secret),
            params={
                "Limit": max(1, min(int(limit), 500)),
                "Sort": "ArrivedAt DESC",
            },
            timeout=20,
        )
    except Exception as exc:
        return {"success": False, "error": str(exc), "entries": []}

    if resp.status_code != 200:
        return {"success": False, "error": f"HTTP {resp.status_code}", "entries": []}

    try:
        payload = resp.json()
    except Exception:
        return {"success": False, "error": "Invalid Mailjet response", "entries": []}

    rows = payload.get("Data") or []
    info_rows = []
    info_error = None
    info_resp = _fetch_mailjet_message_information(limit=limit)
    if info_resp.get("success"):
        info_rows = info_resp.get("rows") or []
    else:
        info_error = info_resp.get("error")
    rows = [row for row in rows if _mailjet_record_in_lookback(row, cutoff_dt)]
    info_rows = [row for row in info_rows if _mailjet_record_in_lookback(row, cutoff_dt)]
    info_by_id = {str(row.get("ID")): row for row in info_rows if row.get("ID") is not None}

    normalized = []
    normalized_resource_ids = set()
    normalized_index_by_resource_id = {}
    for row in rows:
        row_id = row.get("ID")
        info_row = info_by_id.get(str(row_id)) if row_id is not None else None
        record = _normalize_mailjet_message_record(row, info_row)
        normalized.append(record)
        if record.get("message_resource_id") is not None:
            rid_key = str(record.get("message_resource_id"))
            normalized_resource_ids.add(rid_key)
            normalized_index_by_resource_id[rid_key] = len(normalized) - 1

    # Mailjet sometimes returns an empty /message list while /messageinformation still
    # has recent records. Resolve those IDs back through /message/{id} so we can recover
    # full log rows without creating blank entries.
    fallback_resolved = 0
    fallback_checked = 0
    max_fallback = min(max(10, int(limit or 200)), 30)

    def _has_display_meta(rec):
        return any([
            str((rec or {}).get("to") or "").strip(),
            str((rec or {}).get("from") or "").strip(),
            str((rec or {}).get("subject") or "").strip(),
        ])

    fallback_candidates = []
    seen_fallback_ids = set()

    # First, enrich any /message list rows that came back without sender/recipient/subject.
    for rec in normalized:
        rid = rec.get("message_resource_id")
        if rid is None or _has_display_meta(rec):
            continue
        rid_key = str(rid)
        if rid_key in seen_fallback_ids:
            continue
        fallback_candidates.append((rid_key, info_by_id.get(rid_key)))
        seen_fallback_ids.add(rid_key)

    # If everything is blank (or /message returned nothing), also try recent IDs from
    # /messageinformation so sync can repopulate after a log clear.
    if (not normalized or not any(_has_display_meta(rec) for rec in normalized)) and info_rows:
        for info_row in info_rows:
            info_id = info_row.get("ID")
            if info_id is None:
                continue
            rid_key = str(info_id)
            if rid_key in seen_fallback_ids:
                continue
            fallback_candidates.append((rid_key, info_row))
            seen_fallback_ids.add(rid_key)
            if len(fallback_candidates) >= max_fallback:
                break

    for rid_key, info_row in fallback_candidates[:max_fallback]:
        fallback_checked += 1
        msg_resp = _fetch_mailjet_message_row_by_id(rid_key)
        if not msg_resp.get("success"):
            continue
        message_row = msg_resp.get("row")
        if not message_row:
            continue
        record = _normalize_mailjet_message_record(message_row, info_row)
        if not _has_display_meta(record):
            continue
        if rid_key in normalized_index_by_resource_id:
            normalized[normalized_index_by_resource_id[rid_key]] = record
        else:
            normalized.append(record)
            normalized_index_by_resource_id[rid_key] = len(normalized) - 1
            normalized_resource_ids.add(rid_key)
        fallback_resolved += 1
        if len(normalized) >= min(int(limit or 200), 200):
            break

    # Mailjet list/messageinformation responses often omit sender/recipient details but keep
    # SenderID / ContactID. Resolve those so sync can show useful rows and repopulate after clear.
    sender_cache = {}
    contact_cache = {}
    meta_checked = 0
    meta_enriched = 0
    meta_enrich_cap = min(max(20, int(limit or 200)), 30)
    for record in normalized:
        if _has_display_meta(record):
            continue
        if meta_checked >= meta_enrich_cap:
            break
        meta_checked += 1

        sender_id = record.get("sender_id")
        if sender_id is not None and not str(record.get("from") or "").strip():
            sender_key = str(sender_id)
            if sender_key not in sender_cache:
                sender_cache[sender_key] = _fetch_mailjet_sender_row_by_id(sender_id)
            sender_resp = sender_cache.get(sender_key) or {}
            sender_row = sender_resp.get("row") if sender_resp.get("success") else None
            sender_email = str((sender_row or {}).get("Email") or "").strip()
            if sender_email:
                record["from"] = sender_email
                meta_enriched += 1

        contact_id = record.get("contact_id")
        if contact_id is not None and not str(record.get("to") or "").strip():
            contact_key = str(contact_id)
            if contact_key not in contact_cache:
                contact_cache[contact_key] = _fetch_mailjet_contact_row_by_id(contact_id)
            contact_resp = contact_cache.get(contact_key) or {}
            contact_row = contact_resp.get("row") if contact_resp.get("success") else None
            contact_email = str((contact_row or {}).get("Email") or "").strip()
            if contact_email:
                record["to"] = contact_email
                meta_enriched += 1

    # Do not synthesize log rows from messageinformation-only payloads because Mailjet does not
    # provide recipient/sender/subject there, which creates unusable blank log lines.
    normalized = [row for row in normalized if _mailjet_record_in_lookback(row, cutoff_dt)]
    response = {
        "success": True,
        "entries": normalized,
        "lookback": lookback_key,
        "lookback_label": (MAILJET_SYNC_LOOKBACKS.get(lookback_key) or {}).get("label", lookback_key),
    }
    if fallback_checked:
        response["fallback_checked"] = fallback_checked
        response["fallback_resolved"] = fallback_resolved
    if meta_checked:
        response["meta_checked"] = meta_checked
        response["meta_enriched"] = meta_enriched
    if info_error:
        response["warning"] = f"messageinformation unavailable: {info_error}"
    return response


def sync_warmup_log_from_mailjet(limit=200, lookback=None):
    lookback_key = normalize_mailjet_sync_lookback(lookback)
    cutoff_dt = mailjet_sync_lookback_cutoff(lookback_key)
    fetched = fetch_mailjet_recent_messages(limit=limit, lookback=lookback_key)
    payload = load_email_log()
    original_entries = payload.get("entries", [])
    # Drop legacy imported-history rows; Mailjet history API often redacts metadata, making them misleading.
    entries = [e for e in original_entries if str((e or {}).get("source") or "") != "mailjet_poll"]
    removed_import_rows = max(0, len(original_entries) - len(entries))
    by_msg_id = {str(e.get("message_id")): e for e in entries if e.get("message_id") is not None}
    by_msg_uuid = {str(e.get("message_uuid")): e for e in entries if e.get("message_uuid")}
    by_resource_id = {str(e.get("message_resource_id")): e for e in entries if e.get("message_resource_id") is not None}

    updated = 0
    added = 0
    skipped_imported = 0
    if fetched.get("success"):
        for item in fetched.get("entries", []):
            clean_from, clean_to, clean_subject, import_note = _sanitize_mailjet_import_fields(
                item.get("from"),
                item.get("to"),
                item.get("subject"),
            )
            item_from = clean_from
            item_to = clean_to
            item_subject = clean_subject
            msg_id = item.get("message_id")
            msg_uuid = item.get("message_uuid")
            resource_id = item.get("message_resource_id")
            msg_id_key = str(msg_id) if msg_id is not None else None
            msg_uuid_key = str(msg_uuid) if msg_uuid else None
            resource_id_key = str(resource_id) if resource_id is not None else None

            target = None
            if msg_uuid_key and msg_uuid_key in by_msg_uuid:
                target = by_msg_uuid[msg_uuid_key]
            elif msg_id_key and msg_id_key in by_msg_id:
                target = by_msg_id[msg_id_key]
            elif resource_id_key and resource_id_key in by_resource_id:
                target = by_resource_id[resource_id_key]

            if target is not None:
                target["delivery_status"] = item.get("delivery_status") or target.get("delivery_status")
                target["last_event_at"] = item.get("last_event_at") or target.get("last_event_at")
                target["from_email"] = target.get("from_email") or item_from
                target["to"] = target.get("to") or item_to
                target["subject"] = target.get("subject") or item_subject
                if item.get("delivery_status"):
                    target["mailjet_status"] = item.get("delivery_status")
                    target["success"] = _delivery_status_counts_as_success(item.get("delivery_status"))
                if msg_id is not None and not target.get("message_id"):
                    target["message_id"] = msg_id
                    by_msg_id[str(msg_id)] = target
                if msg_uuid and not target.get("message_uuid"):
                    target["message_uuid"] = msg_uuid
                    by_msg_uuid[str(msg_uuid)] = target
                if resource_id is not None and not target.get("message_resource_id"):
                    target["message_resource_id"] = resource_id
                    by_resource_id[str(resource_id)] = target
                updated += 1
            else:
                skipped_imported += 1

    # Targeted refresh for pending sends. Mailjet's list endpoints can lag or return
    # stale "queued" status, but the per-message endpoints usually resolve final state.
    pending_statuses = {"accepted", "queued", "success"}
    pending_entries = [
        e for e in entries
        if e.get("message_id") is not None
        and _normalize_mail_status(e.get("delivery_status") or e.get("mailjet_status")) in pending_statuses
        and _mailjet_record_in_lookback(e, cutoff_dt)
    ]
    pending_entries.sort(key=lambda row: str(row.get("sent_at") or row.get("last_event_at") or ""), reverse=True)
    per_message_limit = min(max(5, int(limit or 200) // 4), 40)
    for target in pending_entries[:per_message_limit]:
        refresh = _fetch_mailjet_message_status_for_id(target.get("message_id"))
        if not refresh.get("success"):
            continue
        item = refresh.get("entry")
        if not item:
            continue
        new_status = item.get("delivery_status") or target.get("delivery_status")
        old_status = _normalize_mail_status(target.get("delivery_status") or target.get("mailjet_status"))
        target["delivery_status"] = new_status
        target["mailjet_status"] = item.get("raw_message_status") or target.get("mailjet_status") or new_status
        target["last_event_at"] = item.get("last_event_at") or target.get("last_event_at")
        target["message_resource_id"] = item.get("message_resource_id") or target.get("message_resource_id")
        target["message_uuid"] = target.get("message_uuid") or item.get("message_uuid")
        target["success"] = _delivery_status_counts_as_success(new_status)
        if _normalize_mail_status(new_status) != old_status:
            updated += 1

    entries.sort(key=lambda row: str(row.get("sent_at") or row.get("last_event_at") or ""), reverse=True)
    if len(entries) > 800:
        entries = entries[:800]
    payload["entries"] = entries
    payload["last_synced_at"] = datetime.now().isoformat()
    payload["mailjet_sync_lookback"] = lookback_key
    payload["mailjet_sync_label"] = (MAILJET_SYNC_LOOKBACKS.get(lookback_key) or {}).get("label", lookback_key)
    payload["mailjet_sync_summary"] = summarize_mailjet_entries(fetched.get("entries", [])) if fetched.get("success") else None
    save_email_log(payload)
    return {
        "success": fetched.get("success", False),
        "error": fetched.get("error"),
        "updated": updated,
        "added": added,
        "removed_imported": removed_import_rows,
        "skipped_imported": skipped_imported,
        "lookback": lookback_key,
        "lookback_label": (MAILJET_SYNC_LOOKBACKS.get(lookback_key) or {}).get("label", lookback_key),
        "last_synced_at": payload["last_synced_at"],
        "summary": payload.get("mailjet_sync_summary") or summarize_warmup_entries(entries),
    }


WARMUP_SUBJECTS = [
    "Confirmation: request received",
    "Account notice: no action required",
    "Service update available",
    "Reminder: scheduled maintenance window",
    "Notification: settings updated",
    "Receipt confirmation",
    "Status update: request in progress",
    "Weekly account summary",
    "Support request update",
    "Message delivery confirmation",
    "System notice: recent activity",
    "Reminder: review pending items",
    "Update: information on file",
    "Follow-up notification",
    "Scheduled service reminder",
]

WARMUP_BODIES = [
    "Hello,\n\nThis is an automated notification confirming that your recent request was received successfully. No action is required at this time.\n\nThank you",
    "Hello,\n\nThis is a routine service notice to confirm that your account settings are current. No changes are needed.\n\nRegards",
    "Hello,\n\nA scheduled system process completed successfully for your account. This message is for confirmation purposes only.\n\nThank you",
    "Hello,\n\nThis is a reminder that a maintenance window is scheduled for a future date. No action is required unless you receive a separate follow-up notice.\n\nRegards",
    "Hello,\n\nWe are sending a standard status update to confirm that your information remains on file and accessible.\n\nThank you",
    "Hello,\n\nThis is an automated receipt confirmation for a recent submission. Please keep this message for your records.\n\nRegards",
    "Hello,\n\nYour request is still being processed and no response is needed at this time. A follow-up notice will be sent if additional information is required.\n\nThank you",
    "Hello,\n\nThis is a routine weekly summary notification. No action is required unless you notice any unexpected changes.\n\nRegards",
    "Hello,\n\nA support-related status update is available. This message is informational and does not require a reply.\n\nThank you",
    "Hello,\n\nThis is an automated message delivery confirmation generated by the system. No further action is needed.\n\nRegards",
]


def render_generation_form(template_name, categories, auto_push):
    return render_template(template_name, categories=categories, defaults=COMPANY_DEFAULTS, auto_push=auto_push)


def process_generation_request(template_name, categories, auto_push):
    domain = request.form.get("domain", "").strip().lower()
    category = request.form.get("category", "").strip().lower()
    company_name = request.form.get("company_name", "").strip()

    if not domain or not category:
        flash("Domain and category are required.", "error")
        return render_generation_form(template_name, categories, auto_push)

    if category not in categories:
        flash(f"Template '{category}' is not available.", "error")
        return render_generation_form(template_name, categories, auto_push)

    if not is_valid_domain(domain):
        flash("Invalid domain name format.", "error")
        return render_generation_form(template_name, categories, auto_push)

    if not company_name:
        company_name = derive_company_name(domain, category)

    try:
        site_dir = generate_site(domain, category, company_name)
        file_count = sum(1 for path in site_dir.rglob("*") if path.is_file())

        status = "generated"
        if auto_push:
            github_result = github_push_site(domain, site_dir)
            if github_result["success"]:
                status = "deployed"
                flash(f"Site deployed! {file_count} files pushed to {github_result['repo_url']}", "success")
            else:
                flash(
                    f"Site generated locally ({file_count} files) but GitHub push failed: {github_result['error']}",
                    "warning",
                )
        else:
            flash(f"Site generated: {file_count} files in output/{domain.replace('.', '-')}/", "success")

        domains_data = load_domains()
        existing = next((d for d in domains_data.get("domains", []) if d.get("name") == domain), None)
        note = f"Generated {category} template as '{company_name}'"
        if existing:
            existing["repo"] = domain.replace(".", "-")
            existing["category"] = category
            existing["companyName"] = company_name
            existing["status"] = status
            existing["notes"] = note
            if not existing.get("purchaseDate"):
                existing["purchaseDate"] = datetime.now().strftime("%Y-%m-%d")
        else:
            domains_data.setdefault("domains", []).append({
                "name": domain,
                "repo": domain.replace(".", "-"),
                "category": category,
                "companyName": company_name,
                "purchaseDate": datetime.now().strftime("%Y-%m-%d"),
                "status": status,
                "notes": note,
            })
        save_domains(domains_data)
        return redirect(url_for("generated_result", domain_name=domain))

    except Exception as e:
        flash(f"Generation failed: {str(e)}", "error")
        return render_generation_form(template_name, categories, auto_push)


def repo_name_to_domain(repo_name):
    clean = (repo_name or "").strip().lower()
    match = re.match(r"^(.+)-([a-z]{2,})$", clean)
    if not match:
        return ""
    label = match.group(1).strip("-")
    if not label:
        return ""
    return f"{label}.{match.group(2)}"


def extract_domain_from_description(description):
    if not description:
        return ""
    candidates = re.findall(r"[a-z0-9][a-z0-9.-]+\.[a-z]{2,}", description.lower())
    for candidate in candidates:
        if is_valid_domain(candidate):
            return candidate
    return ""


def fetch_repo_domain_from_github(owner, repo_name, cfg):
    pages_resp = github_request("GET", f"/repos/{owner}/{repo_name}/pages", cfg=cfg, timeout=20)
    if pages_resp.status_code == 200:
        try:
            cname = (pages_resp.json().get("cname") or "").strip().lower()
            if is_valid_domain(cname):
                return cname
        except Exception:
            pass

    cname_resp = github_request("GET", f"/repos/{owner}/{repo_name}/contents/CNAME", cfg=cfg, timeout=20)
    if cname_resp.status_code == 200:
        try:
            data = cname_resp.json()
            if data.get("encoding") == "base64":
                raw = base64.b64decode((data.get("content") or "").encode("utf-8"))
                cname = raw.decode("utf-8", errors="ignore").strip().splitlines()[0].lower()
                if is_valid_domain(cname):
                    return cname
        except (binascii.Error, IndexError, TypeError, ValueError):
            pass
        except Exception:
            pass
    return ""


def recover_domains_from_github(username=None):
    cfg = load_config()
    owner = (username or cfg.get("github_username", "")).strip()
    if not owner:
        return {"success": False, "error": "GitHub username is required. Set it in Settings first."}

    try:
        resp = github_request(
            "GET",
            f"/users/{owner}/repos",
            cfg=cfg,
            params={"per_page": 100, "type": "owner", "sort": "updated"},
            timeout=30,
        )
    except Exception as e:
        return {"success": False, "error": f"GitHub API request failed: {e}"}

    if resp.status_code != 200:
        return {"success": False, "error": f"GitHub API returned HTTP {resp.status_code}"}

    try:
        repos = resp.json()
    except Exception:
        return {"success": False, "error": "GitHub API returned invalid JSON."}

    if not isinstance(repos, list):
        return {"success": False, "error": "Unexpected GitHub API response format."}

    domains_data = load_domains()
    existing = {d.get("name"): d for d in domains_data.get("domains", []) if d.get("name")}

    scanned = 0
    added = 0
    updated = 0
    recovered = []
    today = datetime.now().strftime("%Y-%m-%d")
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    for repo in repos:
        if repo.get("fork"):
            continue
        if not repo.get("has_pages"):
            continue

        scanned += 1
        repo_name = repo.get("name", "")
        if not repo_name:
            continue

        domain = fetch_repo_domain_from_github(owner, repo_name, cfg)
        if not domain:
            domain = extract_domain_from_description(repo.get("description", ""))
        if not domain:
            domain = repo_name_to_domain(repo_name)

        domain = domain.strip().lower()
        if not is_valid_domain(domain):
            continue

        category = guess_category_from_domain(domain, repo_name)
        company_name = derive_company_name(domain, category)
        recovered_note = f"Recovered from GitHub {owner}/{repo_name} ({stamp})"

        entry = existing.get(domain)
        if entry:
            changed = False
            for key, value in (
                ("repo", repo_name),
                ("category", category),
                ("companyName", company_name),
                ("purchaseDate", (repo.get("created_at") or today)[:10]),
            ):
                if not entry.get(key):
                    entry[key] = value
                    changed = True
            if entry.get("status") in ("", "generated", None):
                entry["status"] = "deployed"
                changed = True
            notes = entry.get("notes", "")
            if recovered_note not in notes:
                entry["notes"] = f"{notes} | {recovered_note}".strip(" |")
                changed = True
            if changed:
                updated += 1
        else:
            domains_data.setdefault("domains", []).append({
                "name": domain,
                "repo": repo_name,
                "category": category,
                "companyName": company_name,
                "purchaseDate": (repo.get("created_at") or today)[:10],
                "status": "deployed",
                "notes": recovered_note,
            })
            existing[domain] = domains_data["domains"][-1]
            added += 1

        recovered.append({"domain": domain, "repo": repo_name, "category": category})

    if added or updated:
        save_domains(domains_data)

    return {
        "success": True,
        "owner": owner,
        "scanned_repos": scanned,
        "added": added,
        "updated": updated,
        "total_recovered": len(recovered),
        "domains": recovered,
    }


# ── Routes ──────────────────────────────────────────────────────


@app.route("/")
def dashboard():
    domains_data = load_domains()
    if refresh_whois_cache(domains_data, max_refresh=12):
        save_domains(domains_data)
    domains = domains_data.get("domains", [])
    scan_state = load_scan_state()
    categories = get_available_categories()
    now = datetime.now().strftime("%Y-%m-%d")
    status_changed = False
    for d in domains:
        if not d.get("category_talos"):
            cat_snapshot = scan_state.get("domains", {}).get(d.get("name", ""), {}).get("categorization", {})
            talos_item = next(
                (
                    item for item in (cat_snapshot.get("results") or [])
                    if item.get("vendor") == "talosintelligence" and item.get("status") == "checked" and item.get("category")
                ),
                None,
            )
            if talos_item:
                d["category_talos"] = _normalize_whitespace(talos_item.get("category", ""))
                d["category"] = d["category_talos"]
                d["category_source"] = "talos"
                d["category_last_updated"] = cat_snapshot.get("scanned_at")
                status_changed = True
        if d.get("category_talos"):
            d["category"] = d.get("category_talos")
            d["category_source"] = "talos"
        d["age_days"], d["age_source"] = resolve_domain_age_days(d)
        vt = {
            "malicious": d.get("vt_malicious", 0),
            "suspicious": d.get("vt_suspicious", 0),
        }
        abuse = {"abuse_score": d.get("abuse_score", 0)}
        urlhaus = {"status": d.get("urlhaus_status")}
        burned, reasons = assess_burned_signals(vt=vt, abuse=abuse, urlhaus=urlhaus)
        if burned and d.get("status") not in ("burned", "retired"):
            d["status"] = "burned"
            d["burned_reason"] = "; ".join(reasons)
            note = d.get("notes", "")
            marker = f"Auto-burned: {d['burned_reason']}"
            if marker not in note:
                d["notes"] = f"{note} | {marker}".strip(" |")
            status_changed = True
    if status_changed:
        save_domains(domains_data)

    stats = {
        "total": len(domains),
        "deployed": sum(1 for d in domains if d.get("status") == "deployed"),
        "aging": sum(1 for d in domains if d.get("status") == "aging"),
        "active": sum(1 for d in domains if d.get("status") == "active"),
        "burned": sum(1 for d in domains if d.get("status") == "burned"),
    }
    return render_template(
        "dashboard.html",
        domains=domains,
        stats=stats,
        services=CATEGORIZATION_SERVICES,
        categories=categories,
        status_options=ALLOWED_DOMAIN_STATUSES,
        now=now,
    )


@app.route("/onboard", methods=["GET", "POST"])
def onboard():
    categories = get_available_categories()
    auto_push = github_auto_push_enabled()
    if request.method == "POST":
        return process_generation_request("onboard.html", categories, auto_push)
    return render_generation_form("onboard.html", categories, auto_push)


@app.route("/domain/<domain_name>")
def domain_detail(domain_name):
    domains_data = load_domains()
    domain = next((d for d in domains_data["domains"] if d["name"] == domain_name), None)
    if not domain:
        flash(f"Domain {domain_name} not found.", "error")
        return redirect(url_for("dashboard"))
    # Check if generated site exists
    site_dir = OUTPUT_DIR / domain_name.replace(".", "-")
    domain["has_output"] = site_dir.is_dir()
    domain["output_path"] = str(site_dir) if site_dir.is_dir() else None
    scan_state = load_scan_state()
    scan_entry = scan_state.get("domains", {}).get(domain_name, {})
    domain["health_snapshot"] = scan_entry.get("health")
    domain["reputation_snapshot"] = scan_entry.get("reputation")
    domain["categorization_snapshot"] = scan_entry.get("categorization")
    domain["scan_history"] = scan_entry.get("history", {"health": [], "reputation": [], "categorization": [], "categorization_submit": []})
    if not domain.get("last_health_scan") and domain.get("health_snapshot"):
        domain["last_health_scan"] = domain["health_snapshot"].get("scanned_at")
    if not domain.get("last_rep_scan") and domain.get("reputation_snapshot"):
        domain["last_rep_scan"] = domain["reputation_snapshot"].get("scanned_at")
    cfg = load_config()
    github_user = cfg.get("github_username", "")
    return render_template("domain_detail.html", domain=domain, services=CATEGORIZATION_SERVICES, github_username=github_user)


@app.route("/api/health-check/<domain_name>")
def api_health_check(domain_name):
    return jsonify(check_domain_http(domain_name))


@app.route("/api/dns-check/<domain_name>")
def api_dns_check(domain_name):
    return jsonify(check_dns_records(domain_name))


@app.route("/api/email-check/<domain_name>")
def api_email_check(domain_name):
    return jsonify(check_email_records(domain_name))


@app.route("/api/categorization-check/<domain_name>")
def api_categorization_check(domain_name):
    """Run categorization-provider scans for a domain."""
    snapshot = run_categorization_snapshot(domain_name)
    return jsonify(snapshot)


@app.route("/api/categorization-check/<domain_name>/<service>")
def api_categorization_check_single(domain_name, service):
    """Run a single categorization provider or reputation check."""
    service_key = (service or "").strip().lower()
    if service_key in CATEGORIZATION_PROVIDERS:
        return jsonify(run_categorization_provider_check(service_key, domain_name))

    checkers = {
        "virustotal": check_virustotal,
        "abuseipdb": check_abuseipdb,
        "urlhaus": check_urlhaus,
    }
    checker = checkers.get(service_key)
    if not checker:
        return jsonify({"error": f"Unknown service: {service_key}"}), 400
    result = checker(domain_name)
    return jsonify(result)


@app.route("/api/categorization/scan/<domain_name>", methods=["GET", "POST"])
def api_categorization_scan(domain_name):
    if request.method == "POST":
        return jsonify(run_categorization_snapshot(domain_name))

    state = load_scan_state()
    entry = state.get("domains", {}).get(domain_name, {})
    snapshot = entry.get("categorization")
    if not snapshot:
        snapshot = run_categorization_snapshot(domain_name)
    return jsonify(snapshot)


@app.route("/api/categorization/submit/<domain_name>", methods=["POST"])
def api_categorization_submit(domain_name):
    return jsonify({
        "success": False,
        "disabled": True,
        "message": "Automatic categorization submission is disabled. Use manual provider links.",
        "domain": domain_name,
    }), 410


@app.route("/api/scan/health/<domain_name>", methods=["POST"])
def api_scan_health(domain_name):
    snapshot = run_health_snapshot(domain_name)
    return jsonify(snapshot)


@app.route("/api/scan/reputation/<domain_name>", methods=["POST"])
def api_scan_reputation(domain_name):
    snapshot = run_reputation_snapshot(domain_name)
    return jsonify(snapshot)


@app.route("/api/scan/full/<domain_name>", methods=["POST"])
def api_scan_full(domain_name):
    snapshot = run_full_snapshot(domain_name)
    return jsonify(snapshot)


@app.route("/api/domain/<domain_name>/status", methods=["POST"])
def api_update_status(domain_name):
    data = request.json
    new_status = str(data.get("status") or "").strip().lower()
    if new_status not in ALLOWED_DOMAIN_STATUSES:
        return jsonify({"error": "Invalid status"}), 400
    domains_data = load_domains()
    for d in domains_data["domains"]:
        if d["name"] == domain_name:
            d["status"] = new_status
            save_domains(domains_data)
            return jsonify({"success": True})
    return jsonify({"error": "Domain not found"}), 404


@app.route("/api/domain/<domain_name>/notes", methods=["POST"])
def api_update_notes(domain_name):
    data = request.json
    domains_data = load_domains()
    for d in domains_data["domains"]:
        if d["name"] == domain_name:
            d["notes"] = data.get("notes", "")
            save_domains(domains_data)
            return jsonify({"success": True})
    return jsonify({"error": "Domain not found"}), 404


@app.route("/generate", methods=["GET", "POST"])
def generate():
    """Generate site files for a domain. Optionally auto-push to GitHub."""
    categories = get_available_categories()
    auto_push = github_auto_push_enabled()

    if request.method == "POST":
        return process_generation_request("generate.html", categories, auto_push)

    return render_generation_form("generate.html", categories, auto_push)


@app.route("/template-demo/<category>")
def template_demo_redirect(category):
    return redirect(url_for("template_demo", category=category), code=302)


@app.route("/template-demo/<category>/", defaults={"filepath": "index.html"})
@app.route("/template-demo/<category>/<path:filepath>")
def template_demo(category, filepath):
    """Serve template files directly from templates/<category>/ with placeholders injected."""
    category = (category or "").strip().lower()
    if category not in get_available_categories():
        return "Template not found", 404

    safe_path = (filepath or "index.html").strip().lstrip("/")
    if not safe_path:
        safe_path = "index.html"
    rel = Path(safe_path)
    if rel.is_absolute() or ".." in rel.parts:
        return "Not found", 404

    demo_domain = f"{category}-example.com"
    demo_company = derive_company_name(demo_domain, category)
    text_mime = {
        ".html": "text/html",
        ".css": "text/css",
        ".js": "application/javascript",
        ".json": "application/json",
        ".txt": "text/plain",
        ".xml": "application/xml",
        ".svg": "image/svg+xml",
    }

    template_file = TEMPLATES_DIR / category / safe_path
    if template_file.is_file():
        suffix = template_file.suffix.lower()
        if suffix in text_mime:
            content = template_file.read_text(encoding="utf-8", errors="ignore")
            content = content.replace("{{COMPANY_NAME}}", demo_company)
            content = content.replace("{{DOMAIN}}", demo_domain)
            return Response(content, mimetype=text_mime[suffix])
        return send_file(template_file)

    return "Not found", 404


@app.route("/generated/<domain_name>")
def generated_result(domain_name):
    """Show the generated site files and deployment instructions."""
    domains_data = load_domains()
    domain = next((d for d in domains_data["domains"] if d["name"] == domain_name), None)
    if not domain:
        flash("Domain not found.", "error")
        return redirect(url_for("dashboard"))

    site_dir = OUTPUT_DIR / domain_name.replace(".", "-")
    if not site_dir.is_dir():
        flash("No generated files found. Generate the site first.", "error")
        return redirect(url_for("generate"))

    # List all files in the output
    files = []
    for fpath in sorted(site_dir.rglob("*")):
        if fpath.is_file():
            rel = fpath.relative_to(site_dir)
            size = fpath.stat().st_size
            files.append({"path": str(rel), "size": size, "abs_path": str(fpath)})

    repo_name = domain_name.replace(".", "-")
    cfg = load_config()
    github_user = cfg.get("github_username", "")
    is_deployed = domain.get("status") == "deployed"

    return render_template(
        "generated_result.html",
        domain=domain,
        files=files,
        output_path=str(site_dir),
        repo_name=repo_name,
        services=CATEGORIZATION_SERVICES,
        github_username=github_user,
        is_deployed=is_deployed,
    )


@app.route("/preview/<domain_name>/<path:filepath>")
def preview_file(domain_name, filepath):
    """Serve a generated file for local preview."""
    site_dir = OUTPUT_DIR / domain_name.replace(".", "-")
    fpath = site_dir / filepath
    if not fpath.is_file() or not fpath.resolve().is_relative_to(site_dir.resolve()):
        return "Not found", 404
    return send_file(fpath)


@app.route("/email")
def email_dashboard():
    domains_data = load_domains()
    domains = [d for d in domains_data.get("domains", []) if d.get("status") not in ("burned", "retired")]
    cfg = load_config()
    email_provider = get_email_provider(cfg)
    email_provider_label = get_email_provider_label(email_provider)
    mailjet_configured = mailjet_provider_configured(cfg)
    mail_provider_configured = current_mail_provider_configured(cfg)
    domain_filter = str(request.args.get("domain") or "").strip().lower()
    log_view = _warmup_log_response(domain_filter=domain_filter, page=1, per_page=WARMUP_LOG_PAGE_SIZE)
    schedule_status = get_warmup_schedule_status()
    return render_template(
        "email.html",
        domains=domains,
        email_provider=email_provider,
        email_provider_label=email_provider_label,
        mail_provider_configured=mail_provider_configured,
        mailjet_configured=mailjet_configured,
        mailjet_sync_enabled=(email_provider == "mailjet" and mailjet_configured),
        mailjet_sync_lookback_default=log_view.get("mailjet_sync_lookback") or DEFAULT_MAILJET_SYNC_LOOKBACK,
        mailjet_sync_lookback_options=[{"key": k, **v} for k, v in MAILJET_SYNC_LOOKBACKS.items()],
        warmup_log=log_view.get("entries", []),
        warmup_summary=log_view.get("summary", {}),
        warmup_summary_label=log_view.get("summary_label"),
        warmup_summary_all=log_view.get("summary_all", {}),
        warmup_last_synced=log_view.get("last_synced_at"),
        warmup_page=log_view.get("page", 1),
        warmup_per_page=log_view.get("per_page", WARMUP_LOG_PAGE_SIZE),
        warmup_total_entries=log_view.get("total_entries", 0),
        warmup_total_pages=log_view.get("total_pages", 1),
        warmup_domain_filter=log_view.get("domain_filter"),
        warmup_schedule=schedule_status,
    )


@app.route("/api/warmup/send", methods=["POST"])
def api_warmup_send():
    data = request.get_json(silent=True) or {}
    from_email = data.get("from_email", "")
    from_name = data.get("from_name", "")
    to_emails = data.get("to_emails", [])
    count = min(int(data.get("count", 1)), 5)
    if not from_email or not to_emails:
        return jsonify({"error": "from_email and to_emails required"}), 400
    batch = execute_warmup_batch(
        from_email=from_email,
        from_name=from_name,
        to_emails=to_emails,
        count=count,
        source="warmup_send",
        batch_meta={"scheduled": False},
        sleep_between_seconds=2,
    )
    if not batch.get("success"):
        return jsonify({"error": batch.get("error"), "results": batch.get("results", []), "summary": batch.get("summary", {})}), 400
    return jsonify({"results": batch.get("results", []), "summary": batch.get("summary", {}), "batch_id": batch.get("batch_id")})


@app.route("/api/warmup/log")
def api_warmup_log():
    page_raw = request.args.get("page", "1")
    per_page_raw = request.args.get("per_page", str(WARMUP_LOG_PAGE_SIZE))
    limit = request.args.get("limit")
    domain_filter = str(request.args.get("domain") or "").strip().lower()
    try:
        page = max(1, int(page_raw))
    except ValueError:
        page = 1
    try:
        per_page = int(per_page_raw)
    except ValueError:
        per_page = WARMUP_LOG_PAGE_SIZE
    if limit and not request.args.get("per_page"):
        try:
            per_page = int(limit)
        except ValueError:
            pass
    per_page = WARMUP_LOG_PAGE_SIZE if per_page > WARMUP_LOG_PAGE_SIZE else max(1, per_page)

    return jsonify(_warmup_log_response(domain_filter=domain_filter, page=page, per_page=per_page))


@app.route("/api/warmup/log/sync", methods=["POST"])
def api_warmup_log_sync():
    if get_email_provider() != "mailjet":
        return jsonify({"success": False, "error": "Mailjet event sync is only available when Mailjet is the selected email provider."}), 400
    payload = request.get_json(silent=True) or {}
    lookback = normalize_mailjet_sync_lookback(payload.get("lookback"))
    limit_raw = payload.get("limit")
    if limit_raw is None:
        limit = (MAILJET_SYNC_LOOKBACKS.get(lookback) or {}).get("limit_hint", 200)
    else:
        try:
            limit = int(limit_raw)
        except (TypeError, ValueError):
            limit = 200
    sync_result = sync_warmup_log_from_mailjet(limit=limit, lookback=lookback)
    status = 200 if sync_result.get("success") else 502
    return jsonify(sync_result), status


@app.route("/api/warmup/log/clear", methods=["POST"])
def api_warmup_log_clear():
    payload = request.get_json(silent=True) or {}
    domain_filter = str(payload.get("domain") or "").strip().lower()
    email_log = load_email_log()
    entries = email_log.get("entries", [])
    before = len(entries)
    if domain_filter:
        kept = []
        removed = 0
        for row in entries:
            from_email = row.get("from_email") or ""
            _, from_domain = _extract_email_domain(from_email)
            scheduled_domain = str(row.get("scheduled_domain") or "").strip().lower()
            if from_domain == domain_filter or scheduled_domain == domain_filter:
                removed += 1
                continue
            kept.append(row)
        email_log["entries"] = kept
    else:
        removed = before
        email_log["entries"] = []
    save_email_log(email_log)
    response = _warmup_log_response(domain_filter=domain_filter, page=1, per_page=WARMUP_LOG_PAGE_SIZE)
    response["success"] = True
    response["removed"] = removed
    return jsonify(response)


@app.route("/api/warmup/schedule")
def api_warmup_schedule_status():
    return jsonify({
        "success": True,
        **get_warmup_schedule_status(),
    })


@app.route("/api/warmup/schedule", methods=["POST"])
def api_warmup_schedule_config():
    payload = request.get_json(silent=True) or {}
    cfg = save_warmup_schedule_config({
        "enabled": bool(payload.get("enabled")),
        "interval_days": max(1, min(_safe_int(payload.get("interval_days"), 1) or 1, 30)),
        "sender_local_part": str(payload.get("sender_local_part") or "noreply").strip().lower(),
        "from_name": str(payload.get("from_name") or "").strip(),
        "to_emails": payload.get("to_emails") or [],
        "selected_domains": payload.get("selected_domains") or [],
        "count": max(1, min(_safe_int(payload.get("count"), 1) or 1, 5)),
    })
    configure_warmup_job()
    return jsonify({
        "success": True,
        **get_warmup_schedule_status(),
        "saved": cfg,
    })


@app.route("/api/warmup/schedule/run", methods=["POST"])
def api_warmup_schedule_run():
    result = run_scheduled_warmup_cycle()
    status_code = 200 if result.get("success") else 400
    payload = {
        "success": bool(result.get("success")),
        "result": result.get("result"),
        "error": result.get("error"),
    }
    payload.update(get_warmup_schedule_status())
    return jsonify(payload), status_code


@app.route("/settings", methods=["GET", "POST"])
def settings():
    cfg = load_config()
    if request.method == "POST":
        cfg["email_provider"] = normalize_email_provider(request.form.get("email_provider", DEFAULT_EMAIL_PROVIDER))
        cfg["github_username"] = request.form.get("github_username", "").strip()
        cfg["github_pat"] = request.form.get("github_pat", "").strip()
        cfg["github_auto_push"] = bool(request.form.get("github_auto_push"))
        cfg["mailjet_api_key"] = request.form.get("mailjet_api_key", "").strip()
        cfg["mailjet_api_secret"] = request.form.get("mailjet_api_secret", "").strip()
        cfg["smtp2go_api_key"] = request.form.get("smtp2go_api_key", "").strip()
        cfg["virustotal_api_key"] = request.form.get("virustotal_api_key", "").strip()
        cfg["abuseipdb_api_key"] = request.form.get("abuseipdb_api_key", "").strip()
        cfg["urlhaus_api_key"] = request.form.get("urlhaus_api_key", "").strip()
        cfg["twocaptcha_api_key"] = request.form.get("twocaptcha_api_key", "").strip()
        cfg["talos_username"] = request.form.get("talos_username", "").strip()
        cfg["talos_password"] = request.form.get("talos_password", "").strip()
        cfg["categorization_browser_fallback"] = bool(request.form.get("categorization_browser_fallback"))
        cfg.pop("submission_email", None)
        cfg.pop("watchguard_username", None)
        cfg.pop("watchguard_password", None)
        save_config(cfg)
        flash("Settings saved.", "success")
        return redirect(url_for("settings"))
    return render_template(
        "settings.html",
        config=cfg,
        email_provider=normalize_email_provider(cfg.get("email_provider")),
        email_provider_options=[{"key": key, **value} for key, value in EMAIL_PROVIDER_OPTIONS.items()],
    )


# ── Connection test endpoints ──────────────────────────────────


@app.route("/api/test/github")
def api_test_github():
    cfg = load_config()
    if not cfg.get("github_pat"):
        return jsonify({"success": False, "error": "Not configured"})
    try:
        resp = github_api("GET", "/user", cfg)
        if resp.status_code == 200:
            user = resp.json().get("login", "unknown")
            return jsonify({"success": True, "user": user})
        else:
            return jsonify({"success": False, "error": f"HTTP {resp.status_code}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/test/mailjet")
def api_test_mailjet():
    cfg = load_config()
    if not cfg.get("mailjet_api_key") or not cfg.get("mailjet_api_secret"):
        return jsonify({"success": False, "error": "Not configured"})
    try:
        resp = requests.get(
            "https://api.mailjet.com/v3/REST/apikey",
            auth=(cfg["mailjet_api_key"], cfg["mailjet_api_secret"]),
            timeout=10,
        )
        if resp.status_code == 200:
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": f"HTTP {resp.status_code}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/test/smtp2go")
def api_test_smtp2go():
    cfg = load_config()
    if not str(cfg.get("smtp2go_api_key") or "").strip():
        return jsonify({"success": False, "error": "Not configured"})
    try:
        resp = _smtp2go_api_request("api_keys/permissions", payload={}, timeout=10)
        if resp.get("success"):
            payload = resp.get("json") or {}
            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            permissions = data.get("permissions") if isinstance(data.get("permissions"), list) else []
            has_send = any(str(p or "").strip() == "/email/send" for p in permissions)
            out = {"success": True}
            if permissions:
                out["permission_count"] = len(permissions)
                out["send_allowed"] = has_send
                if not has_send:
                    out["message"] = "Connected (key may be missing /email/send permission)"
            return jsonify(out)
        status_code = resp.get("status_code")
        error = resp.get("error") or "Request failed"
        return jsonify({"success": False, "error": error, "detail": f"HTTP {status_code}" if status_code else None})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/test/virustotal")
def api_test_virustotal():
    cfg = load_config()
    if not cfg.get("virustotal_api_key"):
        return jsonify({"success": False, "error": "Not configured"})
    try:
        resp = requests.get(
            "https://www.virustotal.com/api/v3/domains/google.com",
            headers={"x-apikey": cfg["virustotal_api_key"]},
            timeout=10,
        )
        if resp.status_code == 200:
            return jsonify({"success": True})
        elif resp.status_code == 401:
            return jsonify({"success": False, "error": "Invalid API key"})
        else:
            return jsonify({"success": False, "error": f"HTTP {resp.status_code}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/test/abuseipdb")
def api_test_abuseipdb():
    cfg = load_config()
    if not cfg.get("abuseipdb_api_key"):
        return jsonify({"success": False, "error": "Not configured"})
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": cfg["abuseipdb_api_key"], "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
            timeout=10,
        )
        if resp.status_code == 200:
            data = (resp.json() or {}).get("data", {})
            return jsonify({
                "success": True,
                "ip": data.get("ipAddress", "8.8.8.8"),
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
            })
        elif resp.status_code in (401, 403):
            return jsonify({"success": False, "error": "Invalid API key"})
        else:
            return jsonify({"success": False, "error": f"HTTP {resp.status_code}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/test/urlhaus")
def api_test_urlhaus():
    try:
        cfg = load_config()
        api_key = re.sub(r"\s+", "", str(cfg.get("urlhaus_api_key", "") or ""))
        if not api_key:
            return jsonify({
                "success": False,
                "error": "Not configured",
                "detail": "URLhaus Auth-Key not loaded from encrypted settings",
            })

        def _probe(method, url, headers, data=None):
            r = requests.request(method, url, headers=headers, data=data, timeout=10)
            body = (r.text or "").strip()
            return r.status_code, body[:220]

        # Auth validation against documented authenticated bulk endpoint.
        auth_status, auth_body = _probe(
            "GET",
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/",
            {"Accept": "application/json", "Auth-Key": api_key},
        )
        if auth_status == 200:
            # Secondary probe verifies host lookup endpoint behavior for Warden's use case.
            host_status, host_body = _probe(
                "POST",
                "https://urlhaus-api.abuse.ch/v1/host/",
                {"Accept": "application/json", "Auth-Key": api_key},
                data={"host": "google.com"},
            )
            if host_status == 200:
                return jsonify({
                    "success": True,
                    "message": "URLhaus API reachable",
                    "key_present": True,
                    "key_length": len(api_key),
                    "host_probe": 200,
                })
            return jsonify({
                "success": False,
                "error": f"Host endpoint HTTP {host_status}",
                "detail": f"Auth OK on /urls/recent; host probe body={host_body[:120]}",
                "key_present": True,
                "key_length": len(api_key),
            })

        unauth_status, unauth_body = _probe(
            "GET",
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/",
            {"Accept": "application/json"},
        )

        if auth_status == 403 and "unknown_auth_key" in auth_body.lower():
            return jsonify({
                "success": False,
                "error": "URLhaus rejected the Auth-Key",
                "detail": f"auth={auth_status}, unauth={unauth_status}, key_len={len(api_key)}",
                "key_present": True,
                "key_length": len(api_key),
            })

        if auth_status == 401:
            return jsonify({
                "success": False,
                "error": "URLhaus returned 401 with saved key",
                "detail": f"Likely key not being sent/accepted. auth={auth_status}, unauth={unauth_status}, key_len={len(api_key)}",
                "key_present": True,
                "key_length": len(api_key),
            })

        return jsonify({
            "success": False,
            "error": f"HTTP {auth_status}",
            "detail": f"auth_body={auth_body[:120]} | unauth={unauth_status} unauth_body={unauth_body[:80]}",
            "key_present": True,
            "key_length": len(api_key),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/test/categorization-engine")
def api_test_categorization_engine():
    probe = categorization_engine_probe(load_config())
    return jsonify({
        "success": probe.get("success", True),
        "engine": probe.get("engine", "native_categorization_v1"),
        "providers": probe.get("providers", []),
        "missing_auth": probe.get("missing_auth", []),
    })


# ── GitHub push endpoint (manual trigger) ──────────────────────


@app.route("/api/github/push/<domain_name>", methods=["POST"])
def api_github_push(domain_name):
    """Manually trigger GitHub push for a domain's generated site."""
    if not github_configured():
        return jsonify({"success": False, "error": "GitHub not configured. Set PAT and username in Settings."})

    site_dir = OUTPUT_DIR / domain_name.replace(".", "-")
    if not site_dir.is_dir():
        return jsonify({"success": False, "error": "No generated files found. Generate the site first."})

    result = github_push_site(domain_name, site_dir)

    if result["success"]:
        # Update domain status to deployed
        domains_data = load_domains()
        for d in domains_data["domains"]:
            if d["name"] == domain_name:
                d["status"] = "deployed"
                d["notes"] = (d.get("notes", "") + f" | Pushed to GitHub {datetime.now().strftime('%Y-%m-%d %H:%M')}").strip(" |")
                break
        save_domains(domains_data)

    return jsonify(result)


@app.route("/api/domains/recover/github", methods=["POST"])
def api_domains_recover_github():
    payload = request.json or {}
    username = (payload.get("username") or "").strip()
    result = recover_domains_from_github(username or None)
    if not result.get("success"):
        return jsonify(result), 400
    return jsonify(result)


@app.route("/api/domain/add", methods=["POST"])
def api_add_domain():
    data = request.json
    domain = data.get("name", "").strip().lower()
    if not domain:
        return jsonify({"error": "Domain name required"}), 400
    if not is_valid_domain(domain):
        return jsonify({"error": "Invalid domain name format"}), 400
    domains_data = load_domains()
    if any(d["name"] == domain for d in domains_data["domains"]):
        return jsonify({"error": "Domain already tracked"}), 409
    requested_status = str(data.get("status") or "deployed").strip().lower()
    if requested_status not in ALLOWED_DOMAIN_STATUSES:
        requested_status = "deployed"
    domains_data["domains"].append({
        "name": domain,
        "repo": domain.replace(".", "-"),
        "category": data.get("category", ""),
        "companyName": data.get("companyName", ""),
        "purchaseDate": data.get("purchaseDate", datetime.now().strftime("%Y-%m-%d")),
        "status": requested_status,
        "notes": data.get("notes", ""),
    })
    save_domains(domains_data)
    return jsonify({"success": True})


@app.route("/api/domain/<domain_name>", methods=["DELETE"])
def api_delete_domain(domain_name):
    domains_data = load_domains()
    domains_data["domains"] = [d for d in domains_data["domains"] if d["name"] != domain_name]
    save_domains(domains_data)
    return jsonify({"success": True})


@app.route("/api/scan/all", methods=["POST"])
def api_scan_all():
    payload = request.json or {}
    scan_type = (payload.get("type") or "full").lower()
    domains = [d.get("name") for d in load_domains().get("domains", []) if d.get("name")]
    results = []
    for domain in domains:
        try:
            if scan_type == "health":
                results.append({"domain": domain, "health": run_health_snapshot(domain)})
            elif scan_type == "reputation":
                results.append({"domain": domain, "reputation": run_reputation_snapshot(domain)})
            else:
                results.append(run_full_snapshot(domain))
        except Exception as e:
            results.append({"domain": domain, "error": str(e)})
    return jsonify({"scan_type": scan_type, "results": results, "scanned_at": datetime.now().isoformat()})


@app.route("/api/monitor/status")
def api_monitor_status():
    state = load_scan_state()
    monitor_cfg = state.get("monitor", {})
    next_run = monitor_next_run_iso(monitor_cfg)
    return jsonify({
        "running": bool(monitor_cfg.get("enabled")),
        "frequency": monitor_cfg.get("frequency", "weekly"),
        "frequencies": {k: v["label"] for k, v in MONITOR_FREQUENCIES.items()},
        "last_run": {"all_checks": monitor_cfg.get("last_full_scan")},
        "next_run": next_run,
    })


@app.route("/api/monitor/config", methods=["POST"])
def api_monitor_config():
    payload = request.json or {}
    enabled = bool(payload.get("enabled"))
    frequency = (payload.get("frequency") or "weekly").lower()
    if frequency not in MONITOR_FREQUENCIES:
        frequency = "weekly"
    state = load_scan_state()
    state["monitor"]["enabled"] = enabled
    state["monitor"]["frequency"] = frequency
    save_scan_state(state)
    configure_monitor_job()
    return jsonify({
        "success": True,
        "enabled": enabled,
        "frequency": frequency,
        "next_run": monitor_next_run_iso(state["monitor"]),
    })


@app.route("/api/monitor/run", methods=["POST"])
def api_monitor_run():
    results = run_full_snapshot_all()
    return jsonify({
        "success": True,
        "results": results,
        "ran_at": datetime.now().isoformat(),
    })


@app.route("/reputation")
def reputation():
    domains_data = load_domains()
    domains = domains_data.get("domains", [])
    cfg = load_config()
    has_vt = bool(cfg.get("virustotal_api_key"))
    has_abuseipdb = bool(cfg.get("abuseipdb_api_key"))
    monitor_cfg = load_scan_state().get("monitor", {})
    return render_template(
        "reputation.html",
        domains=domains,
        services=CATEGORIZATION_SERVICES,
        has_vt=has_vt,
        has_abuseipdb=has_abuseipdb,
        monitor_frequency=monitor_cfg.get("frequency", "weekly"),
        monitor_enabled=monitor_cfg.get("enabled", False),
        monitor_options={k: v["label"] for k, v in MONITOR_FREQUENCIES.items()},
    )


# ── Domain Finder ──────────────────────────────────────────────


@app.route("/domain-finder")
def domain_finder_page():
    categories = get_available_categories()
    return render_template("domain_finder.html", categories=categories)


@app.route("/api/domain-finder/search", methods=["POST"])
def api_domain_finder_search():
    data = request.json or {}
    keyword = data.get("keyword", "")
    category = data.get("category", "")
    tld = data.get("tld", "com")
    min_backlinks = int(data.get("min_backlinks", 5))
    min_age = int(data.get("min_age_years", 1))
    max_results = int(data.get("max_results", 30))
    human_readable_only = bool(data.get("human_readable_only", True))
    available_only = bool(data.get("available_only", True))

    finder = CustomDomainFinder()
    results = finder.search_and_score(
        keyword=keyword or None,
        tld=tld,
        min_backlinks=min_backlinks,
        min_age_years=min_age,
        max_results=max_results,
        category=category or None,
        human_readable_only=human_readable_only,
        available_only=available_only,
    )
    payload = {
        "results": results,
        "engine": finder.engine_name,
        "info": finder.last_info,
    }
    if str(finder.last_info.get("mode", "")).startswith("relaxed"):
        payload["warning"] = (
            "Using relaxed ranking because strict external availability/intel filters returned too few matches."
        )
    return jsonify(payload)


@app.route("/api/domain-finder/whois/<domain_name>")
def api_domain_finder_whois(domain_name):
    finder = DomainFinder()
    info = finder.get_whois_age(domain_name)
    return jsonify(info)


@app.route("/api/domain-finder/wayback/<domain_name>")
def api_domain_finder_wayback(domain_name):
    info = get_wayback_info(domain_name)
    return jsonify(info)


@app.route("/api/domain-finder/virustotal/<domain_name>")
def api_domain_finder_virustotal(domain_name):
    cfg = load_config()
    if not cfg.get("virustotal_api_key", "").strip():
        return jsonify({"error": "VirusTotal API key not configured in Settings."})
    return jsonify(check_virustotal(domain_name))


@app.route("/api/domain-finder/categorization/<domain_name>")
def api_domain_finder_categorization(domain_name):
    return jsonify(build_domain_categorization_intel(domain_name))


@app.route("/api/domain-finder/lookup/<domain_name>")
def api_domain_finder_lookup(domain_name):
    """Comprehensive domain lookup: WHOIS + Wayback + VirusTotal reputation."""
    cfg = load_config()
    finder = DomainFinder()
    result = {"domain": domain_name}

    whois_info = finder.get_whois_age(domain_name)
    result["whois"] = whois_info

    wayback_info = get_wayback_info(domain_name)
    result["wayback"] = wayback_info

    vt_key = cfg.get("virustotal_api_key", "").strip()
    if vt_key:
        vt_result = check_virustotal(domain_name)
        result["virustotal"] = vt_result

    return jsonify(result)


if __name__ == "__main__":
    OUTPUT_DIR.mkdir(exist_ok=True)
    configure_monitor_job()
    configure_warmup_job()
    host = os.environ.get("WARDEN_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("WARDEN_PORT", "5000"))
    except ValueError:
        port = 5000
    debug = str(os.environ.get("WARDEN_DEBUG", "")).strip().lower() in ("1", "true", "yes", "on")

    print("\n  Warden Portal")
    print(f"  http://{host}:{port}")
    print(f"  Output dir: {OUTPUT_DIR}\n")
    app.run(host=host, port=port, debug=debug)
