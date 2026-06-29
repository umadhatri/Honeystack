"""
honeystack – Weekly Report Scheduler
Triggers weekly report generation by calling the API backend every Monday at 00:00 UTC.
"""
import os
import time
import asyncio
import logging
from datetime import datetime, timezone

import schedule
import httpx
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("honeystack.scheduler")

API_URL = os.getenv("API_URL", "http://api:8000/api/v1/reports/generate")

def trigger_report():
    logger.info("Triggering weekly report generation...")
    try:
        resp = httpx.post(API_URL, timeout=30)
        if resp.status_code == 201:
            logger.info(f"Report generated successfully: {resp.json()}")
        else:
            logger.error(f"Failed to generate report: {resp.status_code} - {resp.text}")
    except Exception as e:
        logger.error(f"HTTP request failed: {e}")

def run_scheduler():
    logger.info("Starting schedule loop. Report trigger registered for Monday at 00:00 UTC.")
    # Schedule weekly report generation every Monday at 00:00 UTC
    schedule.every().monday.at("00:00").do(trigger_report)

    # For verification/test, we also trigger a report on start if env has TRIGGER_ON_START=true
    if os.getenv("TRIGGER_ON_START", "false").lower() == "true":
        logger.info("TRIGGER_ON_START is true. Running initial report trigger.")
        trigger_report()

    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    run_scheduler()
