"""
IOC Lookup — checks IP addresses and file hashes against multiple threat intel sources.

Sources used:
  - AlienVault OTX   (free, no key required — but OTX_API_KEY env var raises rate limits)
  - VirusTotal       (free tier; requires VT_API_KEY)
  - AbuseIPDB        (IPs only; requires ABUSEIPDB_API_KEY)
  - Local CVE DB     (always; cross-references enriched IOCs already in your database)

Set in .env:
  VT_API_KEY=...
  ABUSEIPDB_API_KEY=...
  OTX_API_KEY=...   (optional)
"""

import re
import os
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from .database import CVE

logger = logging.getLogger(__name__)

VT_API_KEY       = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY      = os.getenv("OTX_API_KEY", "")
TIMEOUT          = 12.0


# ─── IOC Type Detection ──────────────────────────────────────────────────────

def _extract_domain(value: str) -> str:
    """Extract domain from a URL or return the value as-is if already a domain."""
    from urllib.parse import urlparse
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or value
    # Strip path if present (e.g. "example.com/path")
    return value.split("/")[0].split("?")[0]


def detect_ioc_type(value: str) -> Optional[str]:
    """Detect the IOC type: ipv4, ipv6, md5, sha1, sha256, url, domain, or None."""
    v = value.strip()
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v):
        parts = v.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return "ipv4"
    if re.match(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$', v):
        return "ipv6"
    if re.match(r'^[0-9a-fA-F]{64}$', v):
        return "sha256"
    if re.match(r'^[0-9a-fA-F]{40}$', v):
        return "sha1"
    if re.match(r'^[0-9a-fA-F]{32}$', v):
        return "md5"
    if re.match(r'^https?://', v, re.IGNORECASE):
        return "url"
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', v):
        return "domain"
    return None


def _ts_to_iso(ts) -> Optional[str]:
    """Convert a Unix timestamp (int/float) or ISO string to ISO 8601 string."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return None
    if isinstance(ts, str):
        # Already a string — normalise slightly
        return ts.replace("T", " ").rstrip("Z")
    return None


# ─── AlienVault OTX ─────────────────────────────────────────────────────────

async def _query_otx(indicator_type: str, value: str) -> dict:
    """
    Query AlienVault OTX for an IP or file hash.
    indicator_type: 'IPv4' | 'IPv6' | 'file'
    """
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    base = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{value}"

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(f"{base}/general", headers=headers)
            if resp.status_code == 404:
                return {"source": "AlienVault OTX", "not_found": True, "is_malicious": False}
            if resp.status_code != 200:
                return {"source": "AlienVault OTX", "error": f"HTTP {resp.status_code}"}

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulse_list = pulse_info.get("pulses", [])

            adversaries, malware_families, attack_ids, industries, tags = set(), set(), set(), set(), set()
            campaigns = []

            # Regex patterns that identify threat group names inside OTX tags.
            # OTX contributors routinely tag pulses with APT/FIN/TA labels and
            # known group names even when the structured "adversary" field is empty.
            _APT_RE = re.compile(
                r'^(apt[-\s]?\d+|fin\d+|ta\d+|unc\d+|g\d{4}|'
                r'lazarus|sandworm|turla|cozy.?bear|fancy.?bear|'
                r'equation.?group|carbanak|cobalt.?group|gamaredon|'
                r'sidewinder|mustang.?panda|transparent.?tribe|'
                r'wizard.?spider|scattered.?spider|lapsus|darkside|'
                r'blackcat|lockbit|cl0p|conti|revil|ryuk|emotet|'
                r'trickbot|bazarloader|qakbot|dridex|icedid)$',
                re.IGNORECASE,
            )

            pulse_dates = []
            for pulse in pulse_list:
                created = pulse.get("created")
                if created and isinstance(created, str) and len(created) >= 10:
                    pulse_dates.append(created[:10])

            for pulse in pulse_list:
                # Structured adversary field (often empty, but use it when set)
                adv = (pulse.get("adversary") or "").strip()
                if adv:
                    adversaries.add(adv)

                for mf in pulse.get("malware_families", []):
                    name = mf.get("display_name") or mf.get("id")
                    if name:
                        malware_families.add(name)
                for att in pulse.get("attack_ids", []):
                    aid = att.get("display_name") or att.get("id")
                    if aid:
                        attack_ids.add(aid)
                for ind in pulse.get("industries", []):
                    iname = ind.get("name") or ind.get("slug")
                    if iname:
                        industries.add(iname)
                for t in pulse.get("tags", []):
                    tags.add(t)
                    # Mine tags for threat group names that contributors
                    # put there instead of the structured adversary field
                    if _APT_RE.match(t.strip()):
                        adversaries.add(t.strip().upper().replace("-", "")
                                        if re.match(r'^(apt|fin|ta|unc|g)\d', t, re.I)
                                        else t.strip().title())
                if pulse.get("name"):
                    campaigns.append({
                        "name": pulse["name"],
                        "author": pulse.get("author_name", ""),
                        "created": _ts_to_iso(pulse.get("created")),
                        "description": (pulse.get("description") or "")[:250],
                        "tags": pulse.get("tags", [])[:6],
                        "tlp": pulse.get("tlp", ""),
                        "targeted_countries": pulse.get("targeted_countries", [])[:5],
                        "adversary": pulse.get("adversary", ""),
                        "malware_families": [m.get("display_name") for m in pulse.get("malware_families", []) if m.get("display_name")],
                    })

            # For IPs: extra geo/ASN fields
            country  = data.get("country_name") or data.get("country_code")
            asn      = data.get("asn")
            city     = data.get("city")
            latitude = data.get("latitude")
            longitude = data.get("longitude")

            # For hashes: file metadata
            file_info = {}
            if indicator_type == "file":
                file_info = {
                    "file_type": data.get("type"),
                    "file_size": data.get("size"),
                    "file_class": data.get("type_title"),
                }

            return {
                "source": "AlienVault OTX",
                "is_malicious": pulse_info.get("count", 0) > 0,
                "pulse_count": pulse_info.get("count", 0),
                "adversaries": sorted(adversaries),
                "malware_families": sorted(malware_families),
                "attack_ids": sorted(attack_ids),
                "industries_targeted": sorted(industries),
                "tags": sorted(tags)[:20],
                "campaigns": campaigns[:10],
                "pulse_dates": pulse_dates,
                "first_seen": _ts_to_iso(data.get("first_seen")),
                "last_seen": _ts_to_iso(data.get("last_seen")),
                "reputation": data.get("reputation", 0),
                # IP-specific
                "country": country,
                "asn": asn,
                "city": city,
                "latitude": latitude,
                "longitude": longitude,
                # Hash-specific
                **file_info,
            }

    except httpx.TimeoutException:
        return {"source": "AlienVault OTX", "error": "Request timed out"}
    except Exception as e:
        logger.warning(f"OTX lookup failed for {value}: {e}")
        return {"source": "AlienVault OTX", "error": str(e)}


# ─── VirusTotal ──────────────────────────────────────────────────────────────

async def _query_virustotal(resource_path: str) -> dict:
    """Query VirusTotal API v3. resource_path example: 'ip_addresses/1.2.3.4' or 'files/<hash>'."""
    if not VT_API_KEY:
        return {"source": "VirusTotal", "skipped": True, "reason": "VT_API_KEY not configured"}

    url = f"https://www.virustotal.com/api/v3/{resource_path}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return {"source": "VirusTotal", "not_found": True, "is_malicious": False}
            if resp.status_code == 401:
                return {"source": "VirusTotal", "error": "Invalid API key"}
            if resp.status_code == 429:
                return {"source": "VirusTotal", "error": "Rate limit reached (free tier: 4 req/min)"}
            if resp.status_code != 200:
                return {"source": "VirusTotal", "error": f"HTTP {resp.status_code}"}

            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            # Extract all detecting engine names & categories
            analysis = attrs.get("last_analysis_results", {})
            detections = []
            for engine, result in analysis.items():
                cat = result.get("category", "")
                if cat in ("malicious", "suspicious"):
                    detections.append({
                        "engine": engine,
                        "category": cat,
                        "result": result.get("result") or cat,
                    })

            # Crowdsourced context (threat groups, campaigns)
            crowd_ctx = attrs.get("crowdsourced_context", [])

            # Threat classification — primary source of malware family names
            threat_class = attrs.get("popular_threat_classification") or {}
            threat_label = threat_class.get("suggested_threat_label")
            threat_categories = [c.get("value") for c in threat_class.get("popular_threat_category", [])]
            # VT "popular_threat_name" values are the cleanest malware family names (e.g. "Remcos", "Emotet")
            malware_families_vt = [n.get("value") for n in threat_class.get("popular_threat_name", []) if n.get("value")]

            # Also mine individual engine detection strings for specific malware names.
            # Skip purely generic tokens — anything left is a useful family name.
            _GENERIC = {
                "malicious", "suspicious", "generic", "heuristic", "unknown",
                "unwanted", "unsafe", "riskware", "adware", "potentially",
                "pua", "pup", "trojan", "backdoor", "ransomware", "virus",
                "worm", "spyware", "rootkit", "dropper", "downloader",
                "win32", "win64", "linux", "macos", "android", "msil",
                "agent", "inject", "crypt", "packed", "obfusc",
            }
            for det in detections:
                raw = (det.get("result") or "").strip()
                # Split on common delimiters, take the most specific token
                for token in re.split(r'[/.\-!_]', raw):
                    token = token.strip().lower()
                    if len(token) > 3 and token not in _GENERIC and not token.isdigit():
                        malware_families_vt.append(token.title())
                        break  # one name per engine is enough

            # Deduplicate while preserving the clean popular_threat_name values first
            seen_mf: set = set()
            deduped_mf = []
            for mf in malware_families_vt:
                key = mf.lower()
                if key not in seen_mf:
                    seen_mf.add(key)
                    deduped_mf.append(mf)

            # File-specific
            file_meta = {}
            if "magic" in attrs or "type_description" in attrs:
                file_meta = {
                    "file_type": attrs.get("type_description"),
                    "file_size": attrs.get("size"),
                    "magic": attrs.get("magic"),
                    "file_names": (attrs.get("names") or [])[:5],
                    "md5": attrs.get("md5"),
                    "sha1": attrs.get("sha1"),
                    "sha256": attrs.get("sha256"),
                    "first_submission": _ts_to_iso(attrs.get("first_submission_date")),
                    "last_submission": _ts_to_iso(attrs.get("last_submission_date")),
                    "times_submitted": attrs.get("times_submitted"),
                    "sandbox_verdicts": list(attrs.get("sandbox_verdicts", {}).values())[:5],
                    "signature_info": attrs.get("signature_info") or {},
                    "threat_label": threat_label,
                    "threat_categories": threat_categories,
                    # ← key is now "malware_families" so the orchestrator picks it up
                    "malware_families": deduped_mf[:20],
                }

            # IP-specific
            ip_meta = {}
            if "country" in attrs or "asn" in attrs:
                ip_meta = {
                    "country": attrs.get("country"),
                    "asn": attrs.get("asn"),
                    "as_owner": attrs.get("as_owner"),
                    "network": attrs.get("network"),
                    "continent": attrs.get("continent"),
                    "tags": attrs.get("tags", []),
                }

            return {
                "source": "VirusTotal",
                "is_malicious": malicious > 0 or suspicious > 0,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}" if total else "0/0",
                "reputation": attrs.get("reputation", 0),
                "last_analysis_date": _ts_to_iso(attrs.get("last_analysis_date")),
                "detections": detections[:20],
                "crowdsourced_context": crowd_ctx[:5],
                **file_meta,
                **ip_meta,
            }

    except httpx.TimeoutException:
        return {"source": "VirusTotal", "error": "Request timed out"}
    except Exception as e:
        logger.warning(f"VirusTotal lookup failed for {resource_path}: {e}")
        return {"source": "VirusTotal", "error": str(e)}


# ─── AbuseIPDB ───────────────────────────────────────────────────────────────

async def _query_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation (IPs only)."""
    if not ABUSEIPDB_API_KEY:
        return {"source": "AbuseIPDB", "skipped": True, "reason": "ABUSEIPDB_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 180, "verbose": True},
            )
            if resp.status_code != 200:
                return {"source": "AbuseIPDB", "error": f"HTTP {resp.status_code}"}

            d = resp.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)

            # Aggregate reported categories
            category_map = {
                3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
                6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
                9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
                12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
                15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
                18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
                21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
            }
            reports = d.get("reports") or []
            all_categories = set()
            for r in reports:
                for cat_id in (r.get("categories") or []):
                    label = category_map.get(cat_id)
                    if label:
                        all_categories.add(label)

            return {
                "source": "AbuseIPDB",
                "is_malicious": score >= 25,
                "abuse_confidence_score": score,
                "total_reports": d.get("totalReports", 0),
                "distinct_users": d.get("numDistinctUsers", 0),
                "last_reported_at": d.get("lastReportedAt"),
                "country": d.get("countryCode"),
                "domain": d.get("domain"),
                "isp": d.get("isp"),
                "usage_type": d.get("usageType"),
                "is_tor": d.get("isTor", False),
                "hostnames": d.get("hostnames", [])[:5],
                "reported_categories": sorted(all_categories),
                "recent_reports": [
                    {
                        "reported_at": r.get("reportedAt"),
                        "comment": (r.get("comment") or "")[:200],
                        "categories": [category_map.get(c, str(c)) for c in (r.get("categories") or [])],
                    }
                    for r in reports[:5]
                ],
            }

    except httpx.TimeoutException:
        return {"source": "AbuseIPDB", "error": "Request timed out"}
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {"source": "AbuseIPDB", "error": str(e)}


# ─── Local CVE DB cross-reference ────────────────────────────────────────────

def _search_local_db(value: str, db: Session) -> list:
    """Find approved CVEs whose enriched IOC list contains this value."""
    value_lower = value.lower()
    matches = []

    cves = (db.query(CVE)
            .filter(CVE.status == "approved", CVE.iocs.isnot(None))
            .all())

    for cve in cves:
        if not cve.iocs:
            continue
        for ioc in cve.iocs:
            if not isinstance(ioc, dict):
                continue
            if value_lower in (ioc.get("value") or "").lower():
                matches.append({
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "ioc_type": ioc.get("type"),
                    "ioc_description": ioc.get("description"),
                    "threat_actors": cve.threat_actors or [],
                    "mitre_techniques": [t.get("id") for t in (cve.mitre_techniques or [])][:5],
                    "published_date": cve.published_date.strftime("%Y-%m-%d") if cve.published_date else None,
                })
                break  # only one match per CVE

    return matches[:10]


# ─── Main Orchestrator ───────────────────────────────────────────────────────

async def lookup_ioc(value: str, db: Session) -> dict:
    """
    Full IOC lookup. Returns a structured result dict with:
      - verdict, is_malicious, first_seen
      - threat_groups, malware_families, attack_types
      - per-source raw data
      - local CVE DB cross-references
    """
    value = value.strip()
    ioc_type = detect_ioc_type(value)

    if not ioc_type:
        return {
            "error": (
                "Unrecognised format. Please enter a valid "
                "IPv4 address, IPv6 address, MD5 hash, SHA1 hash, SHA256 hash, URL, or domain."
            )
        }

    result: dict = {
        "value": value,
        "type": ioc_type,
        "sources": [],
        "is_malicious": False,
        "verdict": "unknown",
        "confidence": "low",
        "first_seen": None,
        "last_seen": None,
        "threat_groups": [],
        "malware_families": [],
        "attack_types": [],
        "industries_targeted": [],
        "tags": [],
        "local_cve_matches": [],
        # IP extras
        "country": None,
        "asn": None,
        "city": None,
        "isp": None,
        # Hash extras
        "file_type": None,
        "file_size": None,
        "file_names": [],
        "all_hashes": {},
    }

    # ── Local DB (always) ──────────────────────────────────────────────────
    result["local_cve_matches"] = _search_local_db(value, db)
    if result["local_cve_matches"]:
        result["is_malicious"] = True

    # ── IP lookup ─────────────────────────────────────────────────────────
    if ioc_type in ("ipv4", "ipv6"):
        otx_type = "IPv4" if ioc_type == "ipv4" else "IPv6"

        otx  = await _query_otx(otx_type, value)
        vt   = await _query_virustotal(f"ip_addresses/{value}")
        abuse = await _query_abuseipdb(value)

        result["sources"] = [otx, vt, abuse]

        for src in [otx, vt, abuse]:
            if src.get("is_malicious"):
                result["is_malicious"] = True
            if src.get("adversaries"):
                result["threat_groups"].extend(src["adversaries"])
            if src.get("malware_families"):
                result["malware_families"].extend(src["malware_families"])
            if src.get("attack_ids"):
                result["attack_types"].extend(src["attack_ids"])
            if src.get("reported_categories"):
                result["attack_types"].extend(src["reported_categories"])
            if src.get("industries_targeted"):
                result["industries_targeted"].extend(src["industries_targeted"])
            if src.get("tags"):
                result["tags"].extend(src["tags"])

        # Geo / network info (prefer OTX, fallback to VT, fallback to AbuseIPDB)
        result["country"] = otx.get("country") or vt.get("country") or abuse.get("country")
        result["city"]    = otx.get("city")
        result["asn"]     = otx.get("asn") or vt.get("asn")
        result["isp"]     = vt.get("as_owner") or abuse.get("isp")

        # first/last seen
        result["first_seen"] = otx.get("first_seen")
        result["last_seen"]  = otx.get("last_seen") or vt.get("last_analysis_date")

    # ── URL / Domain lookup ─────────────────────────────────────────────
    elif ioc_type in ("url", "domain"):
        domain = _extract_domain(value) if ioc_type == "url" else value

        otx = await _query_otx("domain", domain)
        vt_domain = await _query_virustotal(f"domains/{domain}")

        # Also check URL directly on VT if it's a full URL
        if ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            vt_url = await _query_virustotal(f"urls/{url_id}")
            result["sources"] = [otx, vt_domain, vt_url]
        else:
            result["sources"] = [otx, vt_domain]

        for src in result["sources"]:
            if src.get("is_malicious"):
                result["is_malicious"] = True
            if src.get("adversaries"):
                result["threat_groups"].extend(src["adversaries"])
            if src.get("malware_families"):
                result["malware_families"].extend(src["malware_families"])
            if src.get("attack_ids"):
                result["attack_types"].extend(src["attack_ids"])
            if src.get("industries_targeted"):
                result["industries_targeted"].extend(src["industries_targeted"])
            if src.get("tags"):
                result["tags"].extend(src["tags"])

        result["country"] = otx.get("country") or vt_domain.get("country")
        result["asn"] = vt_domain.get("asn")
        result["isp"] = vt_domain.get("as_owner")
        result["first_seen"] = otx.get("first_seen")
        result["last_seen"] = otx.get("last_seen") or vt_domain.get("last_analysis_date")

    # ── Hash lookup ───────────────────────────────────────────────────────
    else:
        otx = await _query_otx("file", value)
        vt  = await _query_virustotal(f"files/{value}")

        result["sources"] = [otx, vt]

        for src in [otx, vt]:
            if src.get("is_malicious"):
                result["is_malicious"] = True
            if src.get("adversaries"):
                result["threat_groups"].extend(src["adversaries"])
            if src.get("malware_families"):
                result["malware_families"].extend(src["malware_families"])
            if src.get("attack_ids"):
                result["attack_types"].extend(src["attack_ids"])
            if src.get("industries_targeted"):
                result["industries_targeted"].extend(src["industries_targeted"])
            if src.get("tags"):
                result["tags"].extend(src["tags"])

        # File metadata (prefer VT, fallback to OTX)
        result["file_type"]  = vt.get("file_type") or otx.get("file_type")
        result["file_size"]  = vt.get("file_size") or otx.get("file_size")
        result["file_names"] = vt.get("file_names") or []

        for hash_key in ("md5", "sha1", "sha256"):
            v = vt.get(hash_key)
            if v:
                result["all_hashes"][hash_key.upper()] = v

        # first/last seen
        result["first_seen"] = vt.get("first_submission") or otx.get("first_seen")
        result["last_seen"]  = vt.get("last_submission") or otx.get("last_seen")

    # ── Build daily detection history ─────────────────────────────────────
    day_counts: dict = {}
    for src in result["sources"]:
        for d in src.get("pulse_dates", []):
            if d:
                day_counts[d] = day_counts.get(d, 0) + 1
        for r in src.get("recent_reports", []):
            reported_at = r.get("reported_at") or ""
            if reported_at and len(reported_at) >= 10:
                day_counts[reported_at[:10]] = day_counts.get(reported_at[:10], 0) + 1
    # If no per-day data but we know a first_seen date, seed a single point
    if not day_counts and result.get("first_seen"):
        fs = str(result["first_seen"])
        if len(fs) >= 10:
            day_counts[fs[:10]] = 1
    result["history"] = [{"date": d, "count": c} for d, c in sorted(day_counts.items())]

    # ── Deduplicate aggregated lists ───────────────────────────────────────
    result["threat_groups"]       = sorted(set(g for g in result["threat_groups"] if g))
    result["malware_families"]    = sorted(set(f for f in result["malware_families"] if f))
    result["attack_types"]        = sorted(set(a for a in result["attack_types"] if a))
    result["industries_targeted"] = sorted(set(i for i in result["industries_targeted"] if i))
    result["tags"]                = sorted(set(t for t in result["tags"] if t))[:20]

    # ── Confidence score ──────────────────────────────────────────────────
    sources_flagging = sum(
        1 for s in result["sources"]
        if not s.get("skipped") and not s.get("error") and s.get("is_malicious")
    )
    total_valid = sum(
        1 for s in result["sources"]
        if not s.get("skipped") and not s.get("error") and not s.get("not_found")
    )

    if result["is_malicious"]:
        result["verdict"] = "malicious"
        if sources_flagging >= 2:
            result["confidence"] = "high"
        elif sources_flagging == 1:
            result["confidence"] = "medium"
        else:
            result["confidence"] = "low"
    elif total_valid > 0:
        result["verdict"] = "clean"
        result["confidence"] = "high" if total_valid >= 2 else "medium"
    else:
        result["verdict"] = "unknown"
        result["confidence"] = "low"

    return result
