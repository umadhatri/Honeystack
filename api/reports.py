import os
import json
import logging
from datetime import datetime, timedelta, date
from typing import Dict, Any, List

import httpx
from jinja2 import Template
from fpdf import FPDF
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("honeystack.api.reports")

class SOCReportPDF(FPDF):
    def header(self):
        # Draw a nice dark header bar
        self.set_fill_color(15, 22, 38)
        self.rect(0, 0, 210, 40, 'F')
        
        self.set_text_color(0, 242, 254) # Cyan accent
        self.set_font('helvetica', 'B', 20)
        self.set_y(10)
        self.cell(0, 10, 'HONEYSTACK SOC INTELLIGENCE REPORT', align='C')
        
        self.set_text_color(148, 163, 184) # Muted text
        self.set_font('helvetica', 'I', 10)
        self.set_y(22)
        self.cell(0, 10, 'Weekly Automated Threat Analysis', align='C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} | Confidential - SOC Use Only', align='C')

async def compile_report_data(db: AsyncSession, start_date: date, end_date: date) -> Dict[str, Any]:
    # Calculate dates
    start_dt = datetime.combine(start_date, datetime.min.time())
    end_dt = datetime.combine(end_date, datetime.max.time())
    
    duration = end_date - start_date
    prev_start_dt = start_dt - duration
    prev_end_dt = start_dt - timedelta(seconds=1)

    # 1. Total events (current vs previous)
    curr_events_res = await db.execute(text("SELECT COUNT(*) FROM events WHERE timestamp BETWEEN :start AND :end"), {"start": start_dt, "end": end_dt})
    curr_events = curr_events_res.scalar_one()

    prev_events_res = await db.execute(text("SELECT COUNT(*) FROM events WHERE timestamp BETWEEN :start AND :end"), {"start": prev_start_dt, "end": prev_end_dt})
    prev_events = prev_events_res.scalar_one()

    # 2. Unique IPs
    curr_ips_res = await db.execute(text("SELECT COUNT(DISTINCT source_ip) FROM events WHERE timestamp BETWEEN :start AND :end"), {"start": start_dt, "end": end_dt})
    curr_ips = curr_ips_res.scalar_one()

    prev_ips_res = await db.execute(text("SELECT COUNT(DISTINCT source_ip) FROM events WHERE timestamp BETWEEN :start AND :end"), {"start": prev_start_dt, "end": prev_end_dt})
    prev_ips = prev_ips_res.scalar_one()

    # 3. Sensor distribution
    ssh_res = await db.execute(text("SELECT COUNT(*) FROM events WHERE sensor_type = 'SSH' AND timestamp BETWEEN :start AND :end"), {"start": start_dt, "end": end_dt})
    ssh_events = ssh_res.scalar_one()

    http_res = await db.execute(text("SELECT COUNT(*) FROM events WHERE sensor_type = 'HTTP' AND timestamp BETWEEN :start AND :end"), {"start": start_dt, "end": end_dt})
    http_events = http_res.scalar_one()

    # 4. Top Credentials
    top_creds_res = await db.execute(text("""
        SELECT ssh_username, ssh_password, COUNT(*) AS count
        FROM events
        WHERE sensor_type = 'SSH'
          AND ssh_username IS NOT NULL
          AND timestamp BETWEEN :start AND :end
        GROUP BY ssh_username, ssh_password
        ORDER BY count DESC LIMIT 5
    """), {"start": start_dt, "end": end_dt})
    top_credentials = [dict(r) for r in top_creds_res.mappings().all()]

    # 5. Top Countries
    top_countries_res = await db.execute(text("""
        SELECT COALESCE(p.country, 'Unknown') as country, COUNT(*) AS count
        FROM events e
        JOIN ip_profiles p ON e.source_ip = p.ip
        WHERE e.timestamp BETWEEN :start AND :end
        GROUP BY p.country
        ORDER BY count DESC LIMIT 5
    """), {"start": start_dt, "end": end_dt})
    top_countries = [dict(r) for r in top_countries_res.mappings().all()]

    # 6. Campaigns
    campaigns_res = await db.execute(text("""
        SELECT name, ip_count, last_active
        FROM campaigns
        WHERE last_active BETWEEN :start AND :end
        ORDER BY ip_count DESC LIMIT 5
    """), {"start": start_dt, "end": end_dt})
    detected_campaigns = [dict(r) for r in campaigns_res.mappings().all()]

    # 7. MITRE techniques
    mitre_res = await db.execute(text("""
        SELECT t.technique_id, t.technique_name, COUNT(*) AS count
        FROM mitre_tags t
        JOIN events e ON t.event_id = e.id
        WHERE e.timestamp BETWEEN :start AND :end
        GROUP BY t.technique_id, t.technique_name
        ORDER BY count DESC
    """), {"start": start_dt, "end": end_dt})
    mitre_techniques = [dict(r) for r in mitre_res.mappings().all()]

    # Calculate Deltas
    change_events = round(((curr_events - prev_events) / prev_events * 100), 1) if prev_events > 0 else (100.0 if curr_events > 0 else 0.0)
    change_ips = round(((curr_ips - prev_ips) / prev_ips * 100), 1) if prev_ips > 0 else (100.0 if curr_ips > 0 else 0.0)

    return {
        "start_date": start_date.strftime("%Y-%m-%d"),
        "end_date": end_date.strftime("%Y-%m-%d"),
        "total_events": curr_events,
        "prev_events": prev_events,
        "change_events": change_events,
        "unique_ips": curr_ips,
        "prev_ips": prev_ips,
        "change_ips": change_ips,
        "ssh_events": ssh_events,
        "http_events": http_events,
        "top_credentials": top_credentials,
        "top_countries": top_countries,
        "detected_campaigns": detected_campaigns,
        "mitre_techniques": mitre_techniques,
    }

async def generate_summary(data: Dict[str, Any]) -> str:
    """Generate LLM summary if key is set, fallback to Jinja2 template."""
    openai_key = os.getenv("OPENAI_API_KEY", "")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    
    is_openai = openai_key and not openai_key.startswith("your_") and len(openai_key) > 20
    is_anthropic = anthropic_key and not anthropic_key.startswith("your_") and len(anthropic_key) > 20

    if is_openai:
        try:
            headers = {"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are a senior SOC manager. Write a concise executive summary for a weekly honeypot intelligence report. Format it in 2 paragraphs of grammatically correct prose."},
                    {"role": "user", "content": f"Weekly statistics: {json.dumps(data)}"}
                ],
                "temperature": 0.5
            }
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"].strip()
                else:
                    logger.warning(f"OpenAI summary failed ({resp.status_code}): {resp.text}")
        except Exception as e:
            logger.warning(f"Failed to fetch OpenAI summary: {e}")

    elif is_anthropic:
        try:
            headers = {
                "x-api-key": anthropic_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "claude-3-5-haiku-20241022",
                "max_tokens": 500,
                "messages": [
                    {"role": "user", "content": f"Write a weekly honeypot intelligence report executive summary in 2 paragraphs based on: {json.dumps(data)}"}
                ]
            }
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload)
                if resp.status_code == 200:
                    return resp.json()["content"][0]["text"].strip()
                else:
                    logger.warning(f"Anthropic summary failed ({resp.status_code}): {resp.text}")
        except Exception as e:
            logger.warning(f"Failed to fetch Anthropic summary: {e}")

    # Fallback to Jinja2 template
    template_str = """During the weekly period from {{ start_date }} to {{ end_date }}, the Honeystack threat intelligence platform observed a total of {{ total_events }} security events. This represents a {{ change_events }}% change week-over-week. These attacks originated from {{ unique_ips }} unique source IP addresses, showing a {{ change_ips }}% change compared to the previous logging period.

The SSH sensors registered {{ ssh_events }} brute-force authentication attempts. The primary targeting vector focused on standard administrative credentials. Concurrently, the HTTP sensors exposed to the web registered {{ http_events }} malicious requests scanning for configuration flaws or administrative path access. Overall, the correlation pipeline successfully grouped these incidents into {{ detected_campaigns|length }} distinct campaigns and aligned the attacks against {{ mitre_techniques|length }} observed MITRE ATT&CK techniques."""
    
    t = Template(template_str)
    return t.render(data)

def build_pdf_report(data: Dict[str, Any], summary: str) -> bytes:
    pdf = SOCReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('helvetica', size=11)
    
    # Report Meta info
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, f"Reporting Window: {data['start_date']} to {data['end_date']}", ln=True)
    pdf.cell(0, 10, f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True)
    pdf.ln(5)
    
    # 1. Executive Summary Section
    pdf.set_font('helvetica', 'B', 14)
    pdf.set_text_color(0, 242, 254)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', size=10)
    
    # Multi-cell wrapper to wrap text beautifully
    pdf.multi_cell(0, 6, summary)
    pdf.ln(10)
    
    # 2. Key Metrics Table
    pdf.set_font('helvetica', 'B', 14)
    pdf.set_text_color(0, 242, 254)
    pdf.cell(0, 10, "2. Platform Activity Metrics", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', 'B', 10)
    
    # Table headers
    pdf.cell(60, 8, "Metric", border=1, fill=False)
    pdf.cell(40, 8, "Current Period", border=1, align='C')
    pdf.cell(40, 8, "Previous Period", border=1, align='C')
    pdf.cell(40, 8, "WoW Change (%)", border=1, align='C', ln=True)
    
    pdf.set_font('helvetica', size=10)
    pdf.cell(60, 8, "Total Raw Events", border=1)
    pdf.cell(40, 8, str(data['total_events']), border=1, align='C')
    pdf.cell(40, 8, str(data['prev_events']), border=1, align='C')
    pdf.cell(40, 8, f"{data['change_events']}%", border=1, align='C', ln=True)
    
    pdf.cell(60, 8, "Unique Attacking IPs", border=1)
    pdf.cell(40, 8, str(data['unique_ips']), border=1, align='C')
    pdf.cell(40, 8, str(data['prev_ips']), border=1, align='C')
    pdf.cell(40, 8, f"{data['change_ips']}%", border=1, align='C', ln=True)
    
    pdf.cell(60, 8, "SSH Brute-Force Events", border=1)
    pdf.cell(40, 8, str(data['ssh_events']), border=1, align='C')
    pdf.cell(40, 8, "-", border=1, align='C')
    pdf.cell(40, 8, "-", border=1, align='C', ln=True)
    
    pdf.cell(60, 8, "HTTP Attack Probes", border=1)
    pdf.cell(40, 8, str(data['http_events']), border=1, align='C')
    pdf.cell(40, 8, "-", border=1, align='C')
    pdf.cell(40, 8, "-", border=1, align='C', ln=True)
    pdf.ln(10)
    
    # 3. Top Credentials & Countries (Side by Side or stacked)
    pdf.set_font('helvetica', 'B', 14)
    pdf.set_text_color(0, 242, 254)
    pdf.cell(0, 10, "3. Top Attack Vectors", ln=True)
    pdf.set_text_color(0, 0, 0)
    
    # Top Credentials
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(0, 8, "Top Brute-Forced SSH Credentials:", ln=True)
    pdf.set_font('helvetica', size=10)
    for idx, cred in enumerate(data['top_credentials']):
        pdf.cell(0, 6, f"  #{idx+1}   username: {cred['ssh_username']}  |  password: {cred['ssh_password']}   ({cred['count']} attempts)", ln=True)
    
    pdf.ln(5)
    # Top Countries
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(0, 8, "Top Attacking Countries:", ln=True)
    pdf.set_font('helvetica', size=10)
    for idx, country in enumerate(data['top_countries']):
        pdf.cell(0, 6, f"  #{idx+1}   {country['country']}: {country['count']} events", ln=True)

    pdf.ln(10)
    
    # 4. MITRE Technique Alignment
    pdf.set_font('helvetica', 'B', 14)
    pdf.set_text_color(0, 242, 254)
    pdf.cell(0, 10, "4. Observed MITRE ATT&CK Techniques", ln=True)
    pdf.set_text_color(0, 0, 0)
    
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 8, "Technique ID", border=1)
    pdf.cell(100, 8, "Technique Name", border=1)
    pdf.cell(40, 8, "Observed Matches", border=1, ln=True)
    
    pdf.set_font('helvetica', size=10)
    for tech in data['mitre_techniques'][:8]: # Display top 8
        pdf.cell(40, 8, tech['technique_id'], border=1)
        pdf.cell(100, 8, tech['technique_name'], border=1)
        pdf.cell(40, 8, str(tech['count']), border=1, ln=True)
        
    return pdf.output()
