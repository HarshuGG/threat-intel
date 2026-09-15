"""Email notifications for CVEs awaiting editorial approval."""
import logging
import os
import secrets
from datetime import datetime, timedelta
from html import escape

import httpx
from sqlalchemy.orm import Session

from .database import CVE, EmailReviewBatch

logger = logging.getLogger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"


def _configured() -> bool:
    return bool(
        os.getenv("RESEND_API_KEY")
        and os.getenv("APPROVAL_FROM_EMAIL")
        and os.getenv("APPROVAL_RECIPIENT_EMAIL")
    )


def send_crawl_review_email(db: Session, cve_ids: list[str]) -> bool:
    """Send one review email for a crawl's newly discovered CVEs.

    A random, expiring URL is stored in PostgreSQL. The URL grants access only to
    this batch, allowing approval from the email without exposing the admin panel.
    """
    cve_ids = sorted(set(cve_ids))
    if not cve_ids:
        return False
    if not _configured():
        logger.info("Crawl email is disabled; RESEND_API_KEY and email settings are required")
        return False

    recipient = os.environ["APPROVAL_RECIPIENT_EMAIL"]
    batch = EmailReviewBatch(
        token=secrets.token_urlsafe(32),
        cve_ids=cve_ids,
        recipient=recipient,
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    db.add(batch)
    db.commit()

    base_url = os.getenv("APPROVAL_BASE_URL", "https://intelquarry.com").rstrip("/")
    review_url = f"{base_url}/review/email/{batch.token}"
    cves = db.query(CVE).filter(CVE.cve_id.in_(cve_ids)).order_by(CVE.cve_id).all()
    rows = "".join(
        f"<li><strong>{escape(cve.cve_id)}</strong> — {escape(cve.severity or 'UNSCORED')}"
        f" — {escape((cve.description or '')[:180])}</li>"
        for cve in cves
    )
    html = f"""
    <h2>IntelQuarry: {len(cves)} new CVE{'s' if len(cves) != 1 else ''} to review</h2>
    <p>New CVEs were found by the scheduled collector. They are private until you approve them.</p>
    <ul>{rows}</ul>
    <p><a href=\"{review_url}\">Review and approve these CVEs</a></p>
    <p>This private link expires in seven days.</p>
    """
    payload = {
        "from": os.environ["APPROVAL_FROM_EMAIL"],
        "to": [recipient],
        "subject": f"IntelQuarry: {len(cves)} new CVE{'s' if len(cves) != 1 else ''} awaiting review",
        "html": html,
    }
    try:
        response = httpx.post(
            RESEND_API_URL,
            headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}"},
            json=payload,
            timeout=20,
        )
        response.raise_for_status()
        logger.info("Sent CVE review email for %s findings", len(cves))
        return True
    except httpx.HTTPError as exc:
        logger.error("Could not send CVE review email: %s", exc)
        db.delete(batch)
        db.commit()
        return False
