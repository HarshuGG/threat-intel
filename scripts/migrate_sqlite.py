"""Copy a SQLite backup into configured PostgreSQL; never overwrite existing CVEs.
Usage: DATABASE_URL=... python scripts/migrate_sqlite.py /path/to/backup.db
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app.database import Base, CVE, engine

def migrate(source_path, target):
    source_path = Path(source_path).resolve()
    if not source_path.is_file():
        raise ValueError('Backup does not exist')
    source = create_engine(f'sqlite:///file:{source_path}?mode=ro&uri=true')
    with source.connect() as connection:
        rows = list(connection.execute(select(CVE.__table__)).mappings())
    Base.metadata.create_all(target)
    inserted = 0
    with Session(target) as session, session.begin():
        existing = set(session.scalars(select(CVE.cve_id)))
        for row in rows:
            if row['cve_id'] in existing:
                continue
            session.add(CVE(**{k: v for k, v in row.items() if k != 'id'}))
            existing.add(row['cve_id'])
            inserted += 1
        session.flush()
        stored = {c.cve_id: c for c in session.scalars(select(CVE))}
        assert all(row['cve_id'] in stored for row in rows)
    source.dispose()
    return len(rows), inserted

if __name__ == '__main__':
    if engine.dialect.name != 'postgresql':
        raise SystemExit('Set DATABASE_URL to the destination PostgreSQL database first.')
    try:
        total, inserted = migrate(sys.argv[1], engine)
        print(f'Verified {total} source CVEs; inserted {inserted}; existing records preserved.')
    except Exception:
        raise SystemExit('Migration failed; the data transaction was rolled back. Connection details withheld.') from None
