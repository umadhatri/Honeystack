"""
honeystack – Background Enrichment Worker
Consumes raw events using FOR UPDATE SKIP LOCKED, enriches IPs, classifies credentials,
detects campaigns, and maps events to MITRE ATT&CK techniques.
"""
import os
import sys
import re
import json
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

# ──────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("honeystack.worker")

# ──────────────────────────────────────────────────────────────
# DB & Redis Config
# ──────────────────────────────────────────────────────────────
_raw_url = os.getenv("DATABASE_URL", "postgresql://honeystack_admin:honeystack_secure_pass_123@db:5432/honeystack_db")
DATABASE_URL = _raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(DATABASE_URL, pool_size=5, max_overflow=10, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

REDIS_URL = os.getenv("REDIS_URL", "redis://cache:6379/0")

# ──────────────────────────────────────────────────────────────
# Worker Constants & Config
# ──────────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
CAMPAIGN_THRESHOLD = int(os.getenv("CAMPAIGN_THRESHOLD", "3"))
CAMPAIGN_WINDOW_HOURS = int(os.getenv("CAMPAIGN_WINDOW_HOURS", "1"))

COMMON_USERNAMES = {"root", "admin", "support", "user", "guest", "ubuntu", "debian", "pi"}
COMMON_PASSWORDS = {"root", "admin", "password", "123456", "12345678", "admin123", "password123", "default", "qwerty"}

# ──────────────────────────────────────────────────────────────
# Load MITRE Mapping Config
# ──────────────────────────────────────────────────────────────
MAPPING_FILE = os.path.join(os.path.dirname(__file__), "mitre_mapping.json")
try:
    with open(MAPPING_FILE, "r") as f:
        MITRE_MAPPING = json.load(f).get("rules", [])
except Exception as e:
    logger.error(f"Failed to load MITRE mapping: {e}")
    MITRE_MAPPING = []

# ──────────────────────────────────────────────────────────────
# Helper: IP Enrichment API Clients
# ──────────────────────────────────────────────────────────────
async def get_ip_enrichment(ip: str, redis_client: aioredis.Redis) -> Dict[str, Any]:
    """Retrieve IP enrichment from Redis cache or APIs."""
    cache_key = f"ip_profile:{ip}"
    cached = await redis_client.get(cache_key)
    if cached:
        logger.debug(f"[CACHE HIT] IP profile for {ip}")
        return json.loads(cached)

    logger.info(f"[ENRICH] Fetching profile for {ip}")
    profile = {
        "ip": ip,
        "abuse_score": 0,
        "report_count": 0,
        "country": None,
        "country_code": None,
        "city": None,
        "isp": None,
        "asn": None,
        "org": None,
        "lat": None,
        "lon": None,
    }

    # 1. AbuseIPDB Lookup
    is_abuseipdb_placeholder = not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY.startswith("your_") or "placeholder" in ABUSEIPDB_API_KEY.lower()
    if not is_abuseipdb_placeholder:
        try:
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            }
            params = {"ipAddress": ip}
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    profile["abuse_score"] = data.get("abuseConfidenceScore", 0)
                    profile["report_count"] = data.get("totalReports", 0)
                elif resp.status_code == 429:
                    logger.warning("AbuseIPDB daily API limit reached (429). Skipping abuse reputation score.")
                else:
                    logger.warning(f"AbuseIPDB error {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.warning(f"Failed AbuseIPDB request for {ip}: {e}")
    else:
        logger.debug("AbuseIPDB API key not configured. Skipping abuse reputation score.")

    # 2. ip-api.com Geolocation Lookup
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    profile["country"] = data.get("country")
                    profile["country_code"] = data.get("countryCode")
                    profile["city"] = data.get("city")
                    profile["isp"] = data.get("isp")
                    profile["asn"] = data.get("as")
                    profile["org"] = data.get("org")
                    profile["lat"] = data.get("lat")
                    profile["lon"] = data.get("lon")
                else:
                    logger.warning(f"ip-api returned fail for {ip}: {data.get('message')}")
            else:
                logger.warning(f"ip-api error {resp.status_code}")
    except Exception as e:
        logger.warning(f"Failed ip-api request for {ip}: {e}")

    # Cache result in Redis for 24 hours (86400 seconds)
    try:
        await redis_client.setex(cache_key, 86400, json.dumps(profile))
    except Exception as e:
        logger.error(f"Redis cache set failure: {e}")

    return profile

# ──────────────────────────────────────────────────────────────
# Helper: Save IP Profile
# ──────────────────────────────────────────────────────────────
async def save_ip_profile(profile: Dict[str, Any], db: AsyncSession):
    stmt = text("""
        INSERT INTO ip_profiles (
            ip, abuse_score, report_count, country, country_code, city, isp, asn, org, lat, lon, last_enriched
        ) VALUES (
            :ip, :abuse_score, :report_count, :country, :country_code, :city, :isp, :asn, :org, :lat, :lon, :last_enriched
        )
        ON CONFLICT (ip) DO UPDATE SET
            abuse_score = EXCLUDED.abuse_score,
            report_count = EXCLUDED.report_count,
            country = EXCLUDED.country,
            country_code = EXCLUDED.country_code,
            city = EXCLUDED.city,
            isp = EXCLUDED.isp,
            asn = EXCLUDED.asn,
            org = EXCLUDED.org,
            lat = EXCLUDED.lat,
            lon = EXCLUDED.lon,
            last_enriched = EXCLUDED.last_enriched
    """)
    bound = {**profile, "last_enriched": datetime.utcnow()}
    await db.execute(stmt, bound)

# ──────────────────────────────────────────────────────────────
# Helper: Classify SSH Credentials
# ──────────────────────────────────────────────────────────────
async def classify_and_log_credential(event: Dict[str, Any], db: AsyncSession) -> str:
    username = event.get("ssh_username")
    password = event.get("ssh_password")
    if not username or not password:
        return "custom"

    # Brute force classification
    is_common = username in COMMON_USERNAMES or password in COMMON_PASSWORDS
    classification = "rockyou_top_1000" if is_common else "custom"

    # Check and update/insert credentials
    stmt_check = text("SELECT id, attempt_count FROM credentials WHERE username = :u AND password = :p")
    res = await db.execute(stmt_check, {"u": username, "p": password})
    row = res.one_or_none()

    if row:
        stmt_update = text("""
            UPDATE credentials 
            SET attempt_count = attempt_count + 1, last_seen = :now
            WHERE id = :id
        """)
        await db.execute(stmt_update, {"id": row[0], "now": datetime.utcnow()})
    else:
        stmt_insert = text("""
            INSERT INTO credentials (username, password, classification, first_seen, last_seen, attempt_count)
            VALUES (:u, :p, :c, :now, :now, 1)
        """)
        await db.execute(stmt_insert, {"u": username, "p": password, "c": classification, "now": datetime.utcnow()})

    return classification

# ──────────────────────────────────────────────────────────────
# Helper: MITRE Tagging Logic
# ──────────────────────────────────────────────────────────────
async def tag_mitre_techniques(event: Dict[str, Any], credential_class: str, db: AsyncSession):
    event_id = event["id"]
    tags_to_apply = []

    for rule in MITRE_MAPPING:
        if rule.get("sensor_type") != event["sensor_type"]:
            continue

        matched = False
        cond = rule.get("condition")

        if cond == "ssh_attempt":
            matched = (event["sensor_type"] == "SSH")
        elif cond == "credential_classification_match":
            matched = (event["sensor_type"] == "SSH" and credential_class == "rockyou_top_1000")
        elif cond == "commands_executed":
            matched = (event["sensor_type"] == "SSH" and bool(event.get("ssh_commands")))
        elif cond == "command_match":
            commands = event.get("ssh_commands") or []
            pattern = rule.get("pattern", "")
            if commands and pattern:
                rx = re.compile(pattern, re.IGNORECASE)
                matched = any(rx.search(c) for c in commands)
        elif cond == "path_match":
            path = event.get("http_path") or ""
            pattern = rule.get("pattern", "")
            if path and pattern:
                rx = re.compile(pattern, re.IGNORECASE)
                matched = bool(rx.search(path))
        elif cond == "attack_type_match":
            attack_type = event.get("attack_type") or ""
            target = rule.get("attack_type", "")
            matched = (attack_type.lower() == target.lower())

        if matched:
            tags_to_apply.append((rule["id"], rule["name"]))

    if tags_to_apply:
        stmt_insert = text("""
            INSERT INTO mitre_tags (event_id, technique_id, technique_name)
            VALUES (:event_id, :tech_id, :tech_name)
        """)
        for tech_id, tech_name in tags_to_apply:
            await db.execute(stmt_insert, {"event_id": event_id, "tech_id": tech_id, "tech_name": tech_name})

# ──────────────────────────────────────────────────────────────
# Helper: Coordinated Campaign Detection
# ──────────────────────────────────────────────────────────────
async def detect_and_assign_campaign(event: Dict[str, Any], db: AsyncSession) -> Optional[int]:
    """Detects campaign groupings and assigns campaign_id."""
    now = datetime.utcnow()
    window_start = now - timedelta(hours=CAMPAIGN_WINDOW_HOURS)

    # 1. SSH Credential Match
    if event["sensor_type"] == "SSH" and event.get("ssh_username") and event.get("ssh_password"):
        stmt = text("""
            SELECT DISTINCT source_ip FROM events
            WHERE sensor_type = 'SSH'
              AND ssh_username = :u AND ssh_password = :p
              AND timestamp >= :window_start
        """)
        res = await db.execute(stmt, {"u": event["ssh_username"], "p": event["ssh_password"], "window_start": window_start})
        ips = [row[0] for row in res.all()]
        if len(ips) >= CAMPAIGN_THRESHOLD:
            campaign_name = f"Campaign-SSH-Creds-{event['ssh_username']}-{event['ssh_password']}"
            shared_creds = f"{event['ssh_username']}:{event['ssh_password']}"
            return await get_or_create_campaign(campaign_name, shared_creds=shared_creds, db=db, ip_count=len(ips))

    # 2. HTTP User Agent Match
    if event["sensor_type"] == "HTTP" and event.get("http_user_agent"):
        # Exclude empty or basic/extremely common standard user agents from campaign detection
        ua = event["http_user_agent"].strip()
        if len(ua) > 10 and "mozilla" not in ua.lower():
            stmt = text("""
                SELECT DISTINCT source_ip FROM events
                WHERE sensor_type = 'HTTP'
                  AND http_user_agent = :ua
                  AND timestamp >= :window_start
            """)
            res = await db.execute(stmt, {"ua": ua, "window_start": window_start})
            ips = [row[0] for row in res.all()]
            if len(ips) >= CAMPAIGN_THRESHOLD:
                campaign_name = f"Campaign-HTTP-UA-{hash(ua) % 100000}"
                return await get_or_create_campaign(campaign_name, shared_ua=ua, db=db, ip_count=len(ips))

    # 3. SSH Command Sequence Match
    if event["sensor_type"] == "SSH" and event.get("ssh_commands"):
        # Match only when commands contain non-empty sequences
        cmds = event["ssh_commands"]
        if len(cmds) >= 2:
            cmds_json = json.dumps(cmds)
            stmt = text("""
                SELECT DISTINCT source_ip FROM events
                WHERE sensor_type = 'SSH'
                  AND ssh_commands::text = :cmds
                  AND timestamp >= :window_start
            """)
            res = await db.execute(stmt, {"cmds": cmds_json, "window_start": window_start})
            ips = [row[0] for row in res.all()]
            if len(ips) >= CAMPAIGN_THRESHOLD:
                campaign_name = f"Campaign-SSH-Cmds-{hash(cmds_json) % 100000}"
                return await get_or_create_campaign(campaign_name, shared_cmds=cmds, db=db, ip_count=len(ips))

    return None

async def get_or_create_campaign(
    name: str,
    shared_creds: Optional[str] = None,
    shared_ua: Optional[str] = None,
    shared_cmds: Optional[List[str]] = None,
    db: AsyncSession = None,
    ip_count: int = 1
) -> int:
    """Finds active campaign in last 1 hour or creates a new one."""
    now = datetime.utcnow()
    window_start = now - timedelta(hours=CAMPAIGN_WINDOW_HOURS)

    # Check for existing campaign within the window
    stmt = text("""
        SELECT id FROM campaigns
        WHERE name = :name AND last_active >= :window_start
        LIMIT 1
    """)
    res = await db.execute(stmt, {"name": name, "window_start": window_start})
    row = res.one_or_none()

    if row:
        campaign_id = row[0]
        # Update details
        stmt_upd = text("""
            UPDATE campaigns
            SET last_active = :now, ip_count = GREATEST(ip_count, :ip_count)
            WHERE id = :id
        """)
        await db.execute(stmt_upd, {"now": now, "ip_count": ip_count, "id": campaign_id})
        return campaign_id
    else:
        # Create a new campaign
        stmt_ins = text("""
            INSERT INTO campaigns (name, shared_credentials, shared_user_agent, shared_commands, start_time, last_active, ip_count)
            VALUES (:name, :shared_creds::jsonb, :shared_ua, :shared_cmds::jsonb, :now, :now, :ip_count)
            RETURNING id
        """)
        bound = {
            "name": name,
            "shared_creds": json.dumps([shared_creds]) if shared_creds else None,
            "shared_ua": shared_ua,
            "shared_cmds": json.dumps(shared_cmds) if shared_cmds else None,
            "now": now,
            "ip_count": ip_count
        }
        res_ins = await db.execute(stmt_ins, bound)
        return res_ins.scalar_one()

# ──────────────────────────────────────────────────────────────
# Core Processing Loop
# ──────────────────────────────────────────────────────────────
async def process_event(event_row: Any, db: AsyncSession, redis_client: aioredis.Redis):
    # Convert row to dictionary
    event = dict(event_row._mapping)
    logger.info(f"Processing event #{event['id']} from {event['source_ip']}")

    # 1. IP Enrichment & Profile Update
    ip_profile = await get_ip_enrichment(event["source_ip"], redis_client)
    await save_ip_profile(ip_profile, db)

    # 2. SSH Credential Classification
    credential_class = "custom"
    if event["sensor_type"] == "SSH":
        credential_class = await classify_and_log_credential(event, db)

    # 3. Campaign Detection
    campaign_id = await detect_and_assign_campaign(event, db)

    # 4. MITRE Technique Tagging
    await tag_mitre_techniques(event, credential_class, db)

    # 5. Mark Event as Processed & Update Campaign ID
    stmt_finish = text("""
        UPDATE events
        SET processed = TRUE, campaign_id = :campaign_id
        WHERE id = :id
    """)
    await db.execute(stmt_finish, {"id": event["id"], "campaign_id": campaign_id})

async def run_worker():
    logger.info("Initializing redis connections…")
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

    logger.info("Starting worker loop…")
    while True:
        try:
            async with AsyncSessionLocal() as db:
                # Retrieve unprocessed events using FOR UPDATE SKIP LOCKED
                stmt_select = text("""
                    SELECT id, timestamp, sensor_type, source_ip, source_port,
                           ssh_username, ssh_password, ssh_client_version, ssh_commands,
                           http_method, http_path, http_query, http_headers, http_body, http_user_agent, attack_type
                    FROM events
                    WHERE processed = FALSE
                    ORDER BY id ASC
                    LIMIT 20
                    FOR UPDATE SKIP LOCKED
                """)
                result = await db.execute(stmt_select)
                events = result.all()

                if not events:
                    # No events to process, idle sleep
                    await asyncio.sleep(1.0)
                    continue

                for event_row in events:
                    await process_event(event_row, db, redis_client)

                await db.commit()

        except Exception as e:
            logger.error(f"Exception in worker loop: {e}", exc_info=True)
            await asyncio.sleep(2.0)

if __name__ == "__main__":
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        logger.info("Worker stopped by user.")
