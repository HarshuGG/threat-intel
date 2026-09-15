"""
CVE Crawlers — pulls data from NVD and CISA KEV (both free, no key needed).
NVD optional API key for higher rate limits: https://nvd.nist.gov/developers/request-an-api-key
"""
import httpx
import logging
import os
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from .database import CVE, CrawlLog

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _parse_nvd_item(item: dict) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # Description (English preferred)
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")

    # CVSS score — try v3.1, v3.0, v2
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_vector = None
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")
            break

    severity = _severity_from_cvss(cvss_score)

    # References
    references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

    # Affected products (CPE)
    affected_products = []
    cpe_list = []
    configs = cve.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                cpe_list.append(cpe)
                parts = cpe.split(":")
                if len(parts) >= 5:
                    affected_products.append({
                        "vendor": parts[3],
                        "product": parts[4],
                        "version": parts[5] if len(parts) > 5 else "*"
                    })

    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    try:
        pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        pub_dt = datetime.utcnow()

    try:
        mod_dt = datetime.fromisoformat(modified.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        mod_dt = datetime.utcnow()

    title = f"{cve_id} - {description[:80]}..." if len(description) > 80 else f"{cve_id} - {description}"

    return {
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published_date": pub_dt,
        "modified_date": mod_dt,
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "references": references[:20],
        "affected_products": affected_products[:30],
        "cpe_list": cpe_list[:30],
    }


async def crawl_nvd(db: Session, days_back: int = 1) -> dict:
    """Crawl NVD for CVEs published in the last N days."""
    log = CrawlLog(source="nvd", status="running")
    db.add(log)
    db.commit()

    stats = {"new": 0, "updated": 0, "errors": 0}

    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
            "startIndex": 0,
        }
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        async with httpx.AsyncClient(timeout=60) as client:
            while True:
                response = await client.get(NVD_BASE, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                total = data.get("totalResults", 0)

                for item in vulnerabilities:
                    try:
                        parsed = _parse_nvd_item(item)
                        existing = db.query(CVE).filter(CVE.cve_id == parsed["cve_id"]).first()
                        if existing:
                            for k, v in parsed.items():
                                if k != "cve_id":
                                    setattr(existing, k, v)
                            stats["updated"] += 1
                        else:
                            cve_obj = CVE(**parsed)
                            db.add(cve_obj)
                            stats["new"] += 1
                    except Exception as e:
                        logger.error(f"Error processing CVE item: {e}")
                        stats["errors"] += 1

                db.commit()

                # Pagination
                fetched = params["startIndex"] + len(vulnerabilities)
                if fetched >= total:
                    break
                params["startIndex"] = fetched

        log.status = "success"
        log.new_cves = stats["new"]
        log.updated_cves = stats["updated"]
        log.errors = stats["errors"]
        log.message = f"Fetched {stats['new']} new, {stats['updated']} updated CVEs"

    except Exception as e:
        logger.error(f"NVD crawl failed: {e}")
        log.status = "failed"
        log.message = str(e)
        stats["errors"] += 1

    log.finished_at = datetime.utcnow()
    db.commit()
    return stats


async def crawl_cisa_kev(db: Session) -> dict:
    """Sync CISA Known Exploited Vulnerabilities catalog."""
    log = CrawlLog(source="cisa_kev", status="running")
    db.add(log)
    db.commit()

    stats = {"new": 0, "updated": 0, "errors": 0}

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(CISA_KEV_URL)
            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            try:
                cve_id = item.get("cveID", "")
                if not cve_id:
                    continue

                existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()

                if existing:
                    existing.cisa_kev = True
                    existing.exploited_in_wild = True
                    # Update references if not set
                    if not existing.references:
                        existing.references = []
                    stats["updated"] += 1
                else:
                    # Create a basic entry from CISA data
                    pub_str = item.get("dateAdded", "")
                    try:
                        pub_dt = datetime.strptime(pub_str, "%Y-%m-%d")
                    except Exception:
                        pub_dt = datetime.utcnow()

                    vendor = item.get("vendorProject", "")
                    product = item.get("product", "")
                    vuln_name = item.get("vulnerabilityName", "")
                    short_desc = item.get("shortDescription", "")
                    required_action = item.get("requiredAction", "")

                    cve_obj = CVE(
                        cve_id=cve_id,
                        title=f"{cve_id} - {vuln_name}" if vuln_name else cve_id,
                        description=short_desc or f"{vendor} {product} vulnerability.",
                        severity="HIGH",
                        published_date=pub_dt,
                        modified_date=pub_dt,
                        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        affected_products=[{"vendor": vendor, "product": product, "version": "*"}],
                        references=[],
                        cisa_kev=True,
                        exploited_in_wild=True,
                        remediation=required_action,
                    )
                    db.add(cve_obj)
                    stats["new"] += 1

            except Exception as e:
                logger.error(f"Error processing CISA KEV entry: {e}")
                stats["errors"] += 1

        db.commit()
        log.status = "success"
        log.new_cves = stats["new"]
        log.updated_cves = stats["updated"]
        log.message = f"CISA KEV: {stats['new']} new, {stats['updated']} updated"

    except Exception as e:
        logger.error(f"CISA KEV crawl failed: {e}")
        log.status = "failed"
        log.message = str(e)

    log.finished_at = datetime.utcnow()
    db.commit()
    return stats
