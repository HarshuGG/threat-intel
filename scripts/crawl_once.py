"""Scheduled collection independent of the web server; new CVEs stay pending."""
import asyncio
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.database import engine, init_db, SessionLocal, CrawlLog
from app.crawler import crawl_nvd, crawl_cisa_kev

async def main():
    if engine.dialect.name != 'postgresql':
        raise RuntimeError('Scheduled crawling requires persistent PostgreSQL storage')
    init_db()
    with SessionLocal() as db:
        failed = False
        for name, task in [('NVD', lambda: crawl_nvd(db, days_back=2)), ('CISA KEV', lambda: crawl_cisa_kev(db))]:
            result = await task()
            last = db.query(CrawlLog).order_by(CrawlLog.id.desc()).first()
            failed = failed or bool(result.get('errors')) or (last is not None and last.status == 'failed')
            print(f'{name}: new={result["new"]}, updated={result["updated"]}, errors={result["errors"]}')
        if failed:
            raise RuntimeError('One or more crawl sources failed')

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except Exception:
        print('Crawl failed. Check source availability and database configuration. Credentials withheld.', file=sys.stderr)
        sys.exit(1)
