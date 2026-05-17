from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_intel.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)           # CRITICAL, HIGH, MEDIUM, LOW, NONE
    cvss_score = Column(Float)
    cvss_vector = Column(String)
    published_date = Column(DateTime)
    modified_date = Column(DateTime)
    source_url = Column(String)
    references = Column(JSON)           # list of reference URLs

    # Status in review workflow
    status = Column(String, default="pending")   # pending, approved, rejected
    review_notes = Column(Text)
    reviewed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Affected products/vendors
    affected_products = Column(JSON)    # [{"vendor": ..., "product": ..., "versions": ...}]
    cpe_list = Column(JSON)             # CPE strings

    # Enrichment (AI-generated)
    iocs = Column(JSON)                 # [{type, value, description}]
    mitre_techniques = Column(JSON)     # [{id, name, tactic, url, description}]
    attack_vectors = Column(JSON)       # [{step, description}]
    threat_actors = Column(JSON)        # [{name, aliases, description}]
    remediation = Column(Text)
    ai_summary = Column(Text)           # Executive summary for threat hunters
    poc_urls = Column(JSON)             # public PoC links
    poc_available = Column(Boolean, default=False)
    exploited_in_wild = Column(Boolean, default=False)
    cisa_kev = Column(Boolean, default=False)  # in CISA Known Exploited list
    enriched_at = Column(DateTime)
    enrichment_source = Column(String)  # "openai", "anthropic", "mock"


class CrawlLog(Base):
    __tablename__ = "crawl_logs"

    id = Column(Integer, primary_key=True)
    source = Column(String)             # "nvd", "cisa_kev"
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    new_cves = Column(Integer, default=0)
    updated_cves = Column(Integer, default=0)
    errors = Column(Integer, default=0)
    status = Column(String)             # "running", "success", "failed"
    message = Column(Text)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
