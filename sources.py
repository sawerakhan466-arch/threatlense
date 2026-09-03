"""
sources.py
----------
Responsible ONLY for:
    * IOC type detection
    * IOC validation
    * Domain extraction
    * External intelligence/source functions (VirusTotal, WHOIS)
    * The SOURCES registry

This module must NEVER import from app.py. app.py depends on this
module, never the other way around.

Adding a new intelligence source later requires only:
    1. Writing a new get_<source>(ioc, ioc_type) function that returns
       the standard response dictionary described below.
    2. Registering it in the SOURCES dict at the bottom of this file.

No changes to app.py are ever required to add a new source.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any, Callable
from urllib.parse import urlparse

import requests

try:
    import whois as whois_lib  # python-whois
except ImportError:  # pragma: no cover - handled defensively at call time
    whois_lib = None


# --------------------------------------------------------------------------
# Standard response contract
# --------------------------------------------------------------------------
# Every source function MUST return a dict with exactly these keys:
#   {
#       "source": str,
#       "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN" | "ERROR",
#       "risk_score": int (0-100),
#       "raw_data": dict,
#       "error": str | None,
#   }

VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN", "ERROR"}

REQUEST_TIMEOUT_SECONDS = 10


def _empty_result(source_name: str) -> dict[str, Any]:
    """Return a blank, schema-compliant result skeleton."""
    return {
        "source": source_name,
        "verdict": "UNKNOWN",
        "risk_score": 0,
        "raw_data": {},
        "error": None,
    }


def _error_result(source_name: str, message: str) -> dict[str, Any]:
    """Return a schema-compliant result representing a failed lookup."""
    result = _empty_result(source_name)
    result["verdict"] = "ERROR"
    result["error"] = message
    return result


def _score_to_verdict(score: int) -> str:
    """Map a 0-100 risk score onto the standardized verdict buckets."""
    if score >= 60:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


# --------------------------------------------------------------------------
# IOC type detection / validation / extraction
# --------------------------------------------------------------------------

_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def detect_ioc_type(ioc: str) -> str:
    """
    Determine whether the given string looks like an IP, Domain, or URL.

    Uses only the Python standard library (ipaddress, urllib.parse) and
    never makes an external network call.

    Returns one of: "IP", "Domain", "URL", "Unknown"
    """
    if not ioc or not isinstance(ioc, str):
        return "Unknown"

    candidate = ioc.strip()

    # IP address check
    try:
        ipaddress.ip_address(candidate)
        return "IP"
    except ValueError:
        pass

    # URL check (must have an http/https scheme and a hostname)
    parsed = urlparse(candidate)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        return "URL"

    # Domain check
    if _DOMAIN_PATTERN.match(candidate):
        return "Domain"

    return "Unknown"


def is_valid_ioc(ioc: str, ioc_type: str) -> bool:
    """
    Validate `ioc` according to the explicitly selected `ioc_type`.
    Never raises - any parsing failure simply yields False.
    """
    if not ioc or not isinstance(ioc, str):
        return False

    candidate = ioc.strip()
    if not candidate:
        return False

    try:
        if ioc_type == "IP":
            ipaddress.ip_address(candidate)
            return True

        if ioc_type == "Domain":
            return bool(_DOMAIN_PATTERN.match(candidate))

        if ioc_type == "URL":
            parsed = urlparse(candidate)
            if parsed.scheme not in ("http", "https"):
                return False
            if not parsed.hostname:
                return False
            # hostname itself should look like a domain or IP
            host = parsed.hostname
            if _DOMAIN_PATTERN.match(host):
                return True
            try:
                ipaddress.ip_address(host)
                return True
            except ValueError:
                return False

        return False
    except (ValueError, Exception):
        return False


def extract_domain(ioc: str) -> str:
    """
    Return the hostname/domain associated with the IOC.
    Falls back to returning the trimmed original value if parsing fails.
    """
    if not ioc or not isinstance(ioc, str):
        return ""

    candidate = ioc.strip()

    # If it's already a bare IP, return as-is.
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass

    # If it has a scheme, parse and use hostname.
    parsed = urlparse(candidate)
    if parsed.hostname:
        return parsed.hostname

    # Otherwise assume it's already a bare domain.
    return candidate


# --------------------------------------------------------------------------
# VirusTotal source
# --------------------------------------------------------------------------

def get_virustotal(ioc: str, ioc_type: str) -> dict[str, Any]:
    """
    Query VirusTotal for the given IOC and return a standardized result.
    Never raises - all failure modes are captured in the returned dict.
    """
    source_name = "VirusTotal"

    api_key = os.environ.get("VT_API_KEY")
    try:
        import streamlit as st  # local import: avoid hard dependency at import time
        if not api_key and "VT_API_KEY" in st.secrets:
            api_key = st.secrets["VT_API_KEY"]
    except Exception:
        pass

    if not api_key:
        return _error_result(source_name, "VirusTotal API key is not configured.")

    headers = {"x-apikey": api_key}

    try:
        if ioc_type == "IP":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc.strip()}"
        elif ioc_type in ("Domain", "URL"):
            domain = extract_domain(ioc)
            if not domain:
                return _error_result(source_name, "Could not extract a domain to look up.")
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        else:
            return _error_result(source_name, f"Unsupported IOC type: {ioc_type}")

        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)

        if response.status_code == 401:
            return _error_result(source_name, "VirusTotal authentication failed (invalid API key).")
        if response.status_code == 429:
            return _error_result(source_name, "VirusTotal rate limit exceeded. Try again later.")
        if response.status_code == 404:
            result = _empty_result(source_name)
            result["verdict"] = "UNKNOWN"
            result["raw_data"] = {"message": "IOC not found in VirusTotal."}
            return result
        if response.status_code != 200:
            return _error_result(source_name, f"VirusTotal returned HTTP {response.status_code}.")

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        if not stats:
            result = _empty_result(source_name)
            result["verdict"] = "UNKNOWN"
            result["raw_data"] = {"message": "No analysis stats available."}
            return result

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if total <= 0:
            risk_score = 0
        else:
            # Weight malicious detections heavily, suspicious moderately.
            weighted = (malicious * 1.0 + suspicious * 0.5)
            risk_score = int(round(min(100, (weighted / total) * 100)))

        verdict = _score_to_verdict(risk_score)
        if malicious == 0 and suspicious == 0 and total == 0:
            verdict = "UNKNOWN"

        raw_data = {
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "harmless_engines": harmless,
            "undetected_engines": undetected,
            "total_engines": total,
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
        }

        return {
            "source": source_name,
            "verdict": verdict,
            "risk_score": risk_score,
            "raw_data": raw_data,
            "error": None,
        }

    except requests.exceptions.Timeout:
        return _error_result(source_name, "VirusTotal request timed out.")
    except requests.exceptions.RequestException as exc:
        return _error_result(source_name, f"VirusTotal request failed: {exc}")
    except (ValueError, KeyError) as exc:
        return _error_result(source_name, f"Unexpected VirusTotal response structure: {exc}")
    except Exception as exc:  # final safety net - never crash the app
        return _error_result(source_name, f"Unexpected VirusTotal error: {exc}")


# --------------------------------------------------------------------------
# WHOIS source
# --------------------------------------------------------------------------

def _normalize_whois_field(value: Any) -> Any:
    """Normalize a WHOIS field that may be a list, datetime, or scalar."""
    if value is None:
        return None
    if isinstance(value, list):
        # Some registrars return multiple values (e.g. multiple dates).
        normalized = [str(v) for v in value if v is not None]
        return normalized[0] if len(normalized) == 1 else normalized
    return str(value)


def get_whois(ioc: str, ioc_type: str) -> dict[str, Any]:
    """
    Query WHOIS registration data for the given IOC and return a
    standardized, conservative-risk result. WHOIS data alone should
    never be treated as proof of maliciousness.
    """
    source_name = "WHOIS"

    if whois_lib is None:
        return _error_result(source_name, "python-whois library is not installed.")

    try:
        if ioc_type == "IP":
            # python-whois primarily supports domain lookups; IP WHOIS is
            # not reliably supported by this library.
            result = _empty_result(source_name)
            result["verdict"] = "UNKNOWN"
            result["raw_data"] = {
                "message": "WHOIS lookups for raw IP addresses are not supported by this source."
            }
            return result

        domain = extract_domain(ioc)
        if not domain:
            return _error_result(source_name, "Could not extract a domain to look up.")

        record = whois_lib.whois(domain)

        if not record or not getattr(record, "domain_name", None):
            result = _empty_result(source_name)
            result["verdict"] = "UNKNOWN"
            result["raw_data"] = {"message": "No WHOIS record found for this domain."}
            return result

        registrar = _normalize_whois_field(getattr(record, "registrar", None))
        creation_date = _normalize_whois_field(getattr(record, "creation_date", None))
        expiration_date = _normalize_whois_field(getattr(record, "expiration_date", None))
        updated_date = _normalize_whois_field(getattr(record, "updated_date", None))
        name_servers = _normalize_whois_field(getattr(record, "name_servers", None))
        org = _normalize_whois_field(getattr(record, "org", None))
        privacy_protected = False

        registrant_text = " ".join(
            str(v) for v in [registrar, org] if v
        ).lower()
        if any(term in registrant_text for term in ("privacy", "redacted", "protected", "whoisguard")):
            privacy_protected = True

        raw_data = {
            "registrar": registrar,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "updated_date": updated_date,
            "name_servers": name_servers,
            "organization": org,
            "privacy_protected": privacy_protected,
        }

        # Conservative risk scoring: WHOIS data alone never reaches
        # MALICIOUS territory. It can only nudge toward SUSPICIOUS when
        # there are genuinely notable indicators (e.g. very recently
        # created domain), and privacy protection alone is NOT penalized
        # since it is extremely common and legitimate.
        risk_score = 0
        if creation_date and not isinstance(creation_date, list):
            # Best-effort recency check; ignore failures silently.
            try:
                from datetime import datetime, timezone

                created_dt = creation_date
                if isinstance(created_dt, str):
                    # whois lib usually gives datetime objects, but guard
                    # against string forms too.
                    pass
                else:
                    created_dt = None

                original_creation = getattr(record, "creation_date", None)
                if isinstance(original_creation, list):
                    original_creation = original_creation[0] if original_creation else None

                if original_creation and hasattr(original_creation, "tzinfo"):
                    now = datetime.now(original_creation.tzinfo) if original_creation.tzinfo else datetime.now()
                    age_days = (now - original_creation).days
                    if age_days < 30:
                        risk_score = 25  # still SAFE band, but flagged in raw_data
                        raw_data["notable_indicator"] = "Domain registered within the last 30 days."
            except Exception:
                pass

        verdict = "SAFE" if risk_score < 30 else "SUSPICIOUS"
        if not registrar and not creation_date and not name_servers:
            verdict = "UNKNOWN"

        return {
            "source": source_name,
            "verdict": verdict,
            "risk_score": risk_score,
            "raw_data": raw_data,
            "error": None,
        }

    except Exception as exc:  # never crash the app; covers timeouts,
        # unsupported TLDs, library quirks, and unexpected structures.
        return _error_result(source_name, f"WHOIS lookup failed: {exc}")


# --------------------------------------------------------------------------
# Source registry
# --------------------------------------------------------------------------
# app.py must ONLY interact with sources through this registry - never by
# calling get_virustotal / get_whois directly. To add a new source later,
# write a get_<name>(ioc, ioc_type) function above and add one line here.

SOURCES: dict[str, Callable[[str, str], dict[str, Any]]] = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
