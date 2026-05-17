"""
Background scheduler — runs CVE crawling and enrichment automatically.
Crawl interval configurable via env vars.
"""
import logging
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from .database import SessionLocal
from .crawler import crawl_nvd, crawl_cisa_kev
from .enricher import enrich_pending
import os

logger = logging.getLogger(__name__)

CRAWL_INTERVAL_HOURS = int(os.getenv("CRAWL_INTERVAL_HOURS", "6"))
NVD_DAYS_BACK = int(os.getenv("NVD_DAYS_BACK", "2"))

scheduler = AsyncIOScheduler()


async def _run_full_pipeline():
    """Run crawl + enrichment pipeline."""
    db = SessionLocal()
    try:
        logger.info("Starting scheduled NVD crawl...")
        stats = await crawl_nvd(db, days_back=NVD_DAYS_BACK)
        logger.info(f"NVD crawl done: {stats}")

        logger.info("Starting CISA KEV sync...")
        kev_stats = await crawl_cisa_kev(db)
        logger.info(f"CISA KEV sync done: {kev_stats}")

        logger.info("Enriching pending CVEs...")
        enriched = await enrich_pending(db, limit=100)
        logger.info(f"Enriched {enriched} CVEs")

    except Exception as e:
        logger.error(f"Pipeline error: {e}")
    finally:
        db.close()


def setup_scheduler(app):
    """Attach scheduler to FastAPI app lifecycle."""

    @app.on_event("startup")
    async def start_scheduler():
        scheduler.add_job(
            _run_full_pipeline,
            trigger=IntervalTrigger(hours=CRAWL_INTERVAL_HOURS),
            id="full_pipeline",
            name="CVE Crawl + Enrichment",
            replace_existing=True,
        )
        scheduler.start()
        logger.info(f"Scheduler started — crawling every {CRAWL_INTERVAL_HOURS} hours")
        # Run immediately on startup
        asyncio.create_task(_run_full_pipeline())

    @app.on_event("shutdown")
    async def stop_scheduler():
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
