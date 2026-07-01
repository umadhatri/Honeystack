"""
honeystack – FastAPI Ingest & Query Backend
Receives events from sensors, persists to PostgreSQL, and exposes data to the dashboard.
"""
import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, date
from typing import Optional, List

from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func, text
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from reports import compile_report_data, generate_summary, build_pdf_report

load_dotenv()

# ──────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("honeystack.api")

# ──────────────────────────────────────────────────────────────
# DB setup  (asyncpg driver)
# ──────────────────────────────────────────────────────────────
_raw_url = os.getenv("DATABASE_URL", "postgresql://honeystack_admin:honeystack_secure_pass_123@db:5432/honeystack_db")
# asyncpg needs postgresql+asyncpg://…
DATABASE_URL = _raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(DATABASE_URL, pool_size=10, max_overflow=20, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


# ──────────────────────────────────────────────────────────────
# Rate limiter  (1000 events/min on ingest)
# ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)


# ──────────────────────────────────────────────────────────────
# Lifespan
# ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Honeystack API starting up…")
    yield
    await engine.dispose()
    logger.info("Honeystack API shut down.")


# ──────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Honeystack Intelligence API",
    description="Ingest endpoint for SSH/HTTP honeypot sensors + data API for the SOC dashboard.",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tightened in production via env
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────
# Pydantic schemas
# ──────────────────────────────────────────────────────────────
class EventIn(BaseModel):
    sensor_type: str = Field(..., pattern="^(SSH|HTTP)$")
    source_ip: str
    source_port: int

    # SSH fields
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_client_version: Optional[str] = None
    ssh_commands: Optional[List[str]] = None

    # HTTP fields
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_query: Optional[str] = None
    http_headers: Optional[dict] = None
    http_body: Optional[str] = None
    http_user_agent: Optional[str] = None
    attack_type: Optional[str] = None


class EventOut(BaseModel):
    id: int
    timestamp: datetime
    sensor_type: str
    source_ip: str
    source_port: int
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    attack_type: Optional[str] = None

    class Config:
        from_attributes = True


# ──────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["Meta"])
async def health():
    return {"status": "ok", "service": "honeystack-api"}


@app.post("/api/v1/events", tags=["Ingest"], status_code=201)
@limiter.limit("1000/minute")
async def ingest_event(
    request: Request,
    event: EventIn,
    db: AsyncSession = Depends(get_db),
):
    """
    Receive a raw sensor event and persist it to PostgreSQL.
    Rate-limited to 1000 requests/minute per source IP.
    """
    # Build INSERT dynamically from pydantic model
    row = {
        "timestamp": datetime.utcnow(),
        "sensor_type": event.sensor_type,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "ssh_username": event.ssh_username,
        "ssh_password": event.ssh_password,
        "ssh_client_version": event.ssh_client_version,
        "ssh_commands": event.ssh_commands,
        "http_method": event.http_method,
        "http_path": event.http_path,
        "http_query": event.http_query,
        "http_headers": event.http_headers,
        "http_body": event.http_body,
        "http_user_agent": event.http_user_agent,
        "attack_type": event.attack_type,
    }

    stmt = text("""
        INSERT INTO events (
            timestamp, sensor_type, source_ip, source_port,
            ssh_username, ssh_password, ssh_client_version, ssh_commands,
            http_method, http_path, http_query, http_headers,
            http_body, http_user_agent, attack_type
        ) VALUES (
            :timestamp, :sensor_type, :source_ip, :source_port,
            :ssh_username, :ssh_password, :ssh_client_version, CAST(:ssh_commands AS jsonb),
            :http_method, :http_path, :http_query, CAST(:http_headers AS jsonb),
            :http_body, :http_user_agent, :attack_type
        )
        RETURNING id
    """)

    import json as _json
    bound = {**row}
    bound["ssh_commands"] = _json.dumps(event.ssh_commands) if event.ssh_commands else None
    bound["http_headers"] = _json.dumps(event.http_headers) if event.http_headers else None

    result = await db.execute(stmt, bound)
    await db.commit()
    event_id = result.scalar_one()

    logger.info(f"[INGEST] {event.sensor_type} event #{event_id} from {event.source_ip}")
    return {"id": event_id, "status": "accepted"}


@app.get("/api/v1/events", tags=["Dashboard"], response_model=List[EventOut])
async def list_events(
    limit: int = 100,
    offset: int = 0,
    sensor_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Return paginated events, optionally filtered by sensor type or source IP."""
    conditions = []
    params: dict = {"limit": limit, "offset": offset}

    if sensor_type:
        conditions.append("sensor_type = :sensor_type")
        params["sensor_type"] = sensor_type
    if source_ip:
        conditions.append("source_ip = :source_ip")
        params["source_ip"] = source_ip

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    stmt = text(f"""
        SELECT id, timestamp, sensor_type, source_ip, source_port,
               ssh_username, ssh_password, http_method, http_path, attack_type
        FROM events
        {where}
        ORDER BY timestamp DESC
        LIMIT :limit OFFSET :offset
    """)
    result = await db.execute(stmt, params)
    rows = result.mappings().all()
    return [dict(r) for r in rows]


@app.get("/api/v1/stats", tags=["Dashboard"])
async def stats(db: AsyncSession = Depends(get_db)):
    """High-level counts for the dashboard header."""
    result = await db.execute(text("""
        SELECT
            COUNT(*)                                          AS total_events,
            COUNT(DISTINCT source_ip)                        AS unique_ips,
            COUNT(*) FILTER (WHERE sensor_type = 'SSH')      AS ssh_events,
            COUNT(*) FILTER (WHERE sensor_type = 'HTTP')     AS http_events,
            MAX(timestamp)                                   AS last_event
        FROM events
    """))
    row = result.mappings().one()
    return dict(row)


@app.get("/api/v1/top-credentials", tags=["Dashboard"])
async def top_credentials(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Most-attempted SSH username/password pairs."""
    result = await db.execute(text("""
        SELECT ssh_username, ssh_password, COUNT(*) AS attempts
        FROM events
        WHERE sensor_type = 'SSH'
          AND ssh_username IS NOT NULL
        GROUP BY ssh_username, ssh_password
        ORDER BY attempts DESC
        LIMIT :limit
    """), {"limit": limit})
    return [dict(r) for r in result.mappings().all()]


@app.get("/api/v1/top-ips", tags=["Dashboard"])
async def top_ips(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Most active source IPs with event counts."""
    result = await db.execute(text("""
        SELECT source_ip, COUNT(*) AS event_count,
               MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
        FROM events
        GROUP BY source_ip
        ORDER BY event_count DESC
        LIMIT :limit
    """), {"limit": limit})
    return [dict(r) for r in result.mappings().all()]


@app.get("/api/v1/ip/{ip}", tags=["Dashboard"])
async def ip_detail(ip: str, db: AsyncSession = Depends(get_db)):
    """Full enrichment + event history for a specific IP."""
    # IP profile
    profile_result = await db.execute(
        text("SELECT * FROM ip_profiles WHERE ip = :ip"),
        {"ip": ip},
    )
    profile = profile_result.mappings().one_or_none()

    # Events
    events_result = await db.execute(
        text("""
            SELECT id, timestamp, sensor_type, source_port,
                   ssh_username, ssh_password, http_method, http_path, attack_type
            FROM events WHERE source_ip = :ip
            ORDER BY timestamp DESC LIMIT 200
        """),
        {"ip": ip},
    )
    events = [dict(r) for r in events_result.mappings().all()]

    # MITRE tags via event IDs
    if events:
        event_ids = [e["id"] for e in events]
        mitre_result = await db.execute(
            text("""
                SELECT DISTINCT technique_id, technique_name
                FROM mitre_tags
                WHERE event_id = ANY(:ids)
            """),
            {"ids": event_ids},
        )
        mitre_tags = [dict(r) for r in mitre_result.mappings().all()]
    else:
        mitre_tags = []

    return {
        "ip": ip,
        "profile": dict(profile) if profile else None,
        "events": events,
        "mitre_techniques": mitre_tags,
    }


@app.get("/api/v1/campaigns", tags=["Dashboard"])
async def list_campaigns(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Return top active campaigns."""
    result = await db.execute(text("""
        SELECT id, name, shared_credentials, shared_user_agent, shared_commands, start_time, last_active, ip_count
        FROM campaigns
        ORDER BY last_active DESC
        LIMIT :limit
    """), {"limit": limit})
    return [dict(r) for r in result.mappings().all()]


@app.get("/api/v1/sensors", tags=["Dashboard"])
async def sensor_health(db: AsyncSession = Depends(get_db)):
    """Dynamic sensor health check based on last event timestamp."""
    result = await db.execute(text("""
        SELECT sensor_type, MAX(timestamp) as last_seen, COUNT(*) as event_count
        FROM events
        GROUP BY sensor_type
    """))
    return [dict(r) for r in result.mappings().all()]


class ReportGenerateIn(BaseModel):
    start_date: Optional[date] = None
    end_date: Optional[date] = None


@app.post("/api/v1/reports/generate", tags=["Reports"], status_code=201)
async def generate_report_endpoint(
    payload: Optional[ReportGenerateIn] = None,
    db: AsyncSession = Depends(get_db)
):
    """Compile and generate PDF report for a given date range."""
    from datetime import timedelta
    e_date = (payload.end_date if payload and payload.end_date else date.today())
    s_date = (payload.start_date if payload and payload.start_date else e_date - timedelta(days=7))

    # Compile data
    try:
        report_data = await compile_report_data(db, s_date, e_date)
        summary = await generate_summary(report_data)
        pdf_bytes = build_pdf_report(report_data, summary)
    except Exception as e:
        logger.error(f"Report generation compilation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    # Save to PostgreSQL
    import json as _json
    stmt = text("""
        INSERT INTO reports (
            start_date, end_date, total_events, unique_ips,
            top_credentials, top_countries, detected_campaigns, mitre_techniques,
            executive_summary, pdf_content, created_at
        ) VALUES (
            :start_date, :end_date, :total_events, :unique_ips,
            :CAST(:top_credentials AS jsonb), :CAST(:top_countries AS jsonb), :CAST(:detected_campaigns AS jsonb), :CAST(:mitre_techniques AS jsonb),
            :executive_summary, :pdf_content, :created_at
        )
        RETURNING id
    """)

    bound = {
        "start_date": s_date,
        "end_date": e_date,
        "total_events": report_data["total_events"],
        "unique_ips": report_data["unique_ips"],
        "top_credentials": _json.dumps(report_data["top_credentials"]),
        "top_countries": _json.dumps(report_data["top_countries"]),
        "detected_campaigns": _json.dumps(report_data["detected_campaigns"]),
        "mitre_techniques": _json.dumps(report_data["mitre_techniques"]),
        "executive_summary": summary,
        "pdf_content": pdf_bytes,
        "created_at": datetime.utcnow()
    }

    res = await db.execute(stmt, bound)
    await db.commit()
    report_id = res.scalar_one()

    return {"status": "created", "report_id": report_id, "start_date": s_date, "end_date": e_date}


@app.get("/api/v1/reports", tags=["Reports"])
async def list_reports(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """List all generated reports without the large binary PDF blob."""
    result = await db.execute(text("""
        SELECT id, start_date, end_date, total_events, unique_ips, executive_summary, created_at
        FROM reports
        ORDER BY created_at DESC
        LIMIT :limit
    """), {"limit": limit})
    return [dict(r) for r in result.mappings().all()]


@app.get("/api/v1/reports/{id}/download", tags=["Reports"])
async def download_report(id: int, db: AsyncSession = Depends(get_db)):
    """Download a report PDF binary."""
    result = await db.execute(text("""
        SELECT start_date, end_date, pdf_content
        FROM reports
        WHERE id = :id
    """), {"id": id})
    row = result.mappings().one_or_none()
    
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
        
    start_str = row["start_date"].strftime("%Y%m%d")
    end_str = row["end_date"].strftime("%Y%m%d")
    filename = f"honeystack_report_{start_str}_{end_str}.pdf"
    
    return Response(
        content=row["pdf_content"],
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )
