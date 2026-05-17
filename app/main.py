import os
import logging
import secrets
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends, Form, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from .database import get_db, init_db, CVE, CrawlLog
from .crawler import crawl_nvd, crawl_cisa_kev
from .enricher import enrich_cve, enrich_pending
from .scheduler import setup_scheduler
from .ioc_lookup import lookup_ioc

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "changeme")
SITE_NAME = os.getenv("SITE_NAME", "ThreatLens")
SITE_TAGLINE = os.getenv("SITE_TAGLINE", "CVE Intelligence for Threat Hunters")

app = FastAPI(title=SITE_NAME, description=SITE_TAGLINE)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
_jinja_templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "app", "templates"))


def _render(request: Request, name: str, context: dict = None):
    """Compat wrapper — works with both Starlette <1.0 and >=1.0."""
    import inspect
    sig = inspect.signature(_jinja_templates.TemplateResponse)
    params = list(sig.parameters.keys())
    ctx = context or {}
    if params[0] == "request":
        # Starlette >=1.0: TemplateResponse(request, name, context=...)
        return _jinja_templates.TemplateResponse(request, name, context=ctx)
    else:
        # Starlette <1.0: TemplateResponse(name, {"request": request, ...})
        ctx["request"] = request
        return _jinja_templates.TemplateResponse(name, ctx)


templates = _jinja_templates
security = HTTPBasic()


def check_admin(credentials: HTTPBasicCredentials = Depends(security)):
    ok_user = secrets.compare_digest(credentials.username.encode(), ADMIN_USER.encode())
    ok_pass = secrets.compare_digest(credentials.password.encode(), ADMIN_PASS.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def _severity_color(severity: str) -> str:
    return {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "success"}.get(severity or "", "secondary")


templates.env.globals["severity_color"] = _severity_color
templates.env.globals["site_name"] = SITE_NAME
templates.env.globals["site_tagline"] = SITE_TAGLINE
templates.env.globals["now"] = datetime.utcnow


# ─── App Startup ────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    init_db()


setup_scheduler(app)


# ─── Public Routes ───────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request, db: Session = Depends(get_db)):
    recent = (db.query(CVE)
              .filter(CVE.status == "approved")
              .order_by(CVE.published_date.desc())
              .limit(12).all())

    stats = {
        "total": db.query(CVE).filter(CVE.status == "approved").count(),
        "critical": db.query(CVE).filter(CVE.status == "approved", CVE.severity == "CRITICAL").count(),
        "high": db.query(CVE).filter(CVE.status == "approved", CVE.severity == "HIGH").count(),
        "exploited": db.query(CVE).filter(CVE.status == "approved", CVE.exploited_in_wild == True).count(),
        "cisa_kev": db.query(CVE).filter(CVE.status == "approved", CVE.cisa_kev == True).count(),
        "pending": db.query(CVE).filter(CVE.status == "pending").count(),
    }
    return _render(request, "index.html", {"cves": recent, "stats": stats})


@app.get("/cves", response_class=HTMLResponse)
async def browse_cves(
    request: Request,
    db: Session = Depends(get_db),
    severity: Optional[str] = None,
    search: Optional[str] = None,
    exploited: Optional[bool] = None,
    cisa: Optional[bool] = None,
    page: int = Query(default=1, ge=1),
):
    per_page = 20
    q = db.query(CVE).filter(CVE.status == "approved")

    if severity and severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        q = q.filter(CVE.severity == severity)
    if search:
        like = f"%{search}%"
        q = q.filter((CVE.cve_id.ilike(like)) | (CVE.description.ilike(like)) | (CVE.title.ilike(like)))
    if exploited:
        q = q.filter(CVE.exploited_in_wild == True)
    if cisa:
        q = q.filter(CVE.cisa_kev == True)

    total = q.count()
    cves = q.order_by(CVE.published_date.desc()).offset((page - 1) * per_page).limit(per_page).all()
    total_pages = (total + per_page - 1) // per_page

    return _render(request, "cves.html", {
        "cves": cves, "total": total, "page": page,
        "total_pages": total_pages, "severity": severity, "search": search,
        "exploited": exploited, "cisa": cisa,
    })


@app.get("/cve/{cve_id}", response_class=HTMLResponse)
async def cve_detail(request: Request, cve_id: str, db: Session = Depends(get_db)):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id, CVE.status == "approved").first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found or not published")
    return _render(request, "cve_detail.html", {"cve": cve})


# ─── Admin Routes ────────────────────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
):
    pending = db.query(CVE).filter(CVE.status == "pending").order_by(CVE.published_date.desc()).all()
    recent_logs = db.query(CrawlLog).order_by(CrawlLog.started_at.desc()).limit(10).all()
    stats = {
        "pending": len(pending),
        "approved": db.query(CVE).filter(CVE.status == "approved").count(),
        "rejected": db.query(CVE).filter(CVE.status == "rejected").count(),
        "total": db.query(CVE).count(),
        "unenriched": db.query(CVE).filter(CVE.enriched_at.is_(None)).count(),
        "approved_unenriched": db.query(CVE).filter(
            CVE.status == "approved", CVE.enriched_at.is_(None)
        ).count(),
    }
    return _render(request, "admin/dashboard.html", {
        "pending": pending, "logs": recent_logs,
        "stats": stats, "username": username,
    })


@app.get("/admin/review/{cve_id}", response_class=HTMLResponse)
async def admin_review_cve(
    request: Request,
    cve_id: str,
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return _render(request, "admin/review.html", {
        "cve": cve, "username": username,
    })


@app.post("/admin/approve/{cve_id}")
async def approve_cve(
    cve_id: str,
    background_tasks: BackgroundTasks,
    notes: str = Form(default=""),
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    cve.status = "approved"
    cve.review_notes = notes
    cve.reviewed_at = datetime.utcnow()
    db.commit()
    # Auto-enrich if not done yet
    if not cve.enriched_at:
        background_tasks.add_task(enrich_cve, cve, db)
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/api/admin/approve-all")
async def approve_all_pending(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
):
    """Approve all pending CVEs at once and queue them for enrichment."""
    pending = db.query(CVE).filter(CVE.status == "pending").all()
    count = 0
    for cve in pending:
        cve.status = "approved"
        cve.reviewed_at = datetime.utcnow()
        count += 1
        if not cve.enriched_at:
            background_tasks.add_task(enrich_cve, cve, db)
    db.commit()
    return JSONResponse({"approved": count})


@app.post("/admin/reject/{cve_id}")
async def reject_cve(
    cve_id: str,
    notes: str = Form(default=""),
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    cve.status = "rejected"
    cve.review_notes = notes
    cve.reviewed_at = datetime.utcnow()
    db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/enrich/{cve_id}")
async def admin_enrich_cve(
    cve_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    background_tasks.add_task(enrich_cve, cve, db)
    return JSONResponse({"status": "enrichment started", "cve_id": cve_id})


# ─── API Routes ──────────────────────────────────────────────────────────────

@app.get("/api/cves")
async def api_cves(
    db: Session = Depends(get_db),
    severity: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
):
    q = db.query(CVE).filter(CVE.status == "approved")
    if severity:
        q = q.filter(CVE.severity == severity)
    cves = q.order_by(CVE.published_date.desc()).offset(offset).limit(limit).all()
    return [
        {
            "cve_id": c.cve_id,
            "title": c.title,
            "severity": c.severity,
            "cvss_score": c.cvss_score,
            "published_date": c.published_date.isoformat() if c.published_date else None,
            "exploited_in_wild": c.exploited_in_wild,
            "cisa_kev": c.cisa_kev,
            "mitre_techniques": c.mitre_techniques,
            "iocs": c.iocs,
        }
        for c in cves
    ]


@app.post("/api/admin/crawl")
async def trigger_crawl(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
    days_back: int = 2,
):
    """Manually trigger a crawl + enrichment cycle."""
    async def _pipeline():
        await crawl_nvd(db, days_back=days_back)
        await crawl_cisa_kev(db)
        await enrich_pending(db, limit=100)

    background_tasks.add_task(_pipeline)
    return {"status": "crawl started"}


@app.post("/api/admin/enrich-all")
async def trigger_enrich_all(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
):
    """Enrich all CVEs missing enrichment (any status)."""
    background_tasks.add_task(enrich_pending, db, 200)
    return {"status": "bulk enrichment started"}


# ─── IOC Lookup Routes ───────────────────────────────────────────────────────

@app.get("/ioc", response_class=HTMLResponse)
async def ioc_lookup_page(
    request: Request,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
):
    result = None
    if q:
        result = await lookup_ioc(q, db)
    return _render(request, "ioc_lookup.html", {
        "query": q or "", "result": result,
    })


@app.get("/api/ioc")
async def api_ioc_lookup(
    q: str = Query(..., description="IPv4, IPv6, MD5, SHA1, SHA256, URL, or domain"),
    db: Session = Depends(get_db),
):
    """REST endpoint for IOC reputation lookup."""
    return await lookup_ioc(q, db)


@app.post("/api/admin/enrich-approved")
async def trigger_enrich_approved(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    username: str = Depends(check_admin),
):
    """Re-enrich approved CVEs that are missing IOC/MITRE data."""
    async def _enrich_approved():
        # Target approved CVEs with no enrichment OR missing IOCs
        cves = (db.query(CVE)
                .filter(CVE.status == "approved")
                .filter((CVE.enriched_at.is_(None)) | (CVE.iocs.is_(None)))
                .limit(200).all())
        for cve in cves:
            await enrich_cve(cve, db)

    background_tasks.add_task(_enrich_approved)
    return {"status": "enrich-approved started"}
