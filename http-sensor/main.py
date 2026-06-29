"""
honeystack – HTTP Honeypot Sensor
aiohttp web server that serves realistic fake endpoints, detects attack payloads,
tags each request with an attack type, and ships events to the API.
"""
import asyncio
import os
import re
import logging
from datetime import datetime, timezone

from aiohttp import web
import httpx
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────
API_URL   = os.getenv("API_URL", "http://api:8000/api/v1/events")
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))

# ──────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("honeystack.http-sensor")


# ──────────────────────────────────────────────────────────────
# Attack signature patterns  (task 2.6)
# ──────────────────────────────────────────────────────────────
ATTACK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SQLi",            re.compile(r"(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|--|'--|;--|1=1|or\s+1=1|exec\s+xp_)", re.IGNORECASE)),
    ("XSS",             re.compile(r"(<script|javascript:|onerror=|onload=|<img\s.*onerror|<svg\s.*onload)", re.IGNORECASE)),
    ("PathTraversal",   re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)", re.IGNORECASE)),
    ("CmdInjection",    re.compile(r"(;.*\bwget\b|;.*\bcurl\b|`.*`|\$\(.*\)|\|\s*sh|\|\s*bash|nc\s+-)", re.IGNORECASE)),
    ("CredStuffing",    re.compile(r"(password=|passwd=|pass=|pwd=|credential)", re.IGNORECASE)),
    ("Scan",            re.compile(r"(nikto|nmap|masscan|zgrab|sqlmap|dirbuster|gobuster|burpsuite|nuclei)", re.IGNORECASE)),
]


def detect_attack_type(method: str, path: str, query: str, headers: dict, body: str) -> str:
    """Return the first matching attack type, or 'scan' as the catch-all."""
    haystack = " ".join([method, path, query or "", body or "",
                         " ".join(headers.values())]).lower()
    for label, pattern in ATTACK_PATTERNS:
        if pattern.search(haystack):
            return label
    return "scan"


# ──────────────────────────────────────────────────────────────
# Fake response content
# ──────────────────────────────────────────────────────────────
FAKE_ENV = b"""DB_HOST=localhost
DB_PORT=3306
DB_USER=admin
DB_PASSWORD=Sup3rS3cr3t!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

FAKE_GIT_CONFIG = b"""[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = https://github.com/acme/internal-api.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"""

FAKE_WP_LOGIN = b"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Log In &#8212; WordPress</title>
<link rel="stylesheet" href="/wp-includes/css/buttons.min.css" />
</head><body class="login">
<div id="login">
  <h1><a href="https://wordpress.org/">WordPress</a></h1>
  <form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p><label>Username or Email Address<br>
    <input type="text" name="log" size="20" /></label></p>
    <p><label>Password<br>
    <input type="password" name="pwd" size="20" /></label></p>
    <p class="submit"><input type="submit" name="wp-submit" value="Log In" /></p>
    <input type="hidden" name="redirect_to" value="/wp-admin/" />
  </form>
</div>
</body></html>"""

FAKE_ADMIN_LOGIN = b"""<!DOCTYPE html><html>
<head><title>Admin Login</title></head>
<body>
<form action="/admin/login" method="post">
  <input type="text" name="username" placeholder="admin" />
  <input type="password" name="password" placeholder="password" />
  <button type="submit">Login</button>
</form>
</body></html>"""

FAKE_PHPMYADMIN = b"""<!DOCTYPE html><html>
<head><title>phpMyAdmin</title></head>
<body>
<form action="/phpmyadmin/index.php" method="post">
  <input name="pma_username" /><input type="password" name="pma_password" />
  <input type="submit" value="Go" />
</form>
</body></html>"""

FAKE_ACTUATOR = b"""{
  "status": "UP",
  "components": {
    "db": {"status": "UP", "details": {"database": "MySQL", "validationQuery": "isValid()"}},
    "diskSpace": {"status": "UP", "details": {"total": 107374182400, "free": 90000000000}},
    "ping": {"status": "UP"}
  }
}"""

FAKE_API_USERS = b"""{
  "users": [
    {"id": 1, "username": "admin", "email": "admin@example.com", "role": "administrator"},
    {"id": 2, "username": "jdoe",  "email": "jdoe@example.com",  "role": "user"}
  ],
  "total": 2
}"""

FAKE_CONFIG_PHP = b"""<?php
define('DB_NAME',     'wordpressdb');
define('DB_USER',     'wp_admin');
define('DB_PASSWORD', 'P@ssw0rd123!');
define('DB_HOST',     'localhost');
define('AUTH_KEY',    'put your unique phrase here');
"""


# ──────────────────────────────────────────────────────────────
# Event submission
# ──────────────────────────────────────────────────────────────
async def submit_event(payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(API_URL, json=payload)
            if resp.status_code != 201:
                logger.warning(f"API {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logger.error(f"Failed to submit event: {exc}")


# ──────────────────────────────────────────────────────────────
# Middleware: log + tag every request
# ──────────────────────────────────────────────────────────────
@web.middleware
async def log_and_tag(request: web.Request, handler):
    peername = request.transport.get_extra_info("peername") if request.transport else None
    source_ip   = (peername[0] if peername else None) or request.headers.get("X-Forwarded-For", "0.0.0.0").split(",")[0].strip()
    source_port = peername[1] if peername else 0

    body_bytes = await request.read()
    body_text  = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    headers    = dict(request.headers)

    attack_type = detect_attack_type(
        request.method,
        request.path,
        request.query_string,
        headers,
        body_text,
    )

    logger.info(f"[HTTP] {source_ip} {request.method} {request.path} [{attack_type}]")

    # Fire-and-forget to the ingest API
    asyncio.ensure_future(submit_event({
        "sensor_type": "HTTP",
        "source_ip": source_ip,
        "source_port": source_port,
        "http_method": request.method,
        "http_path": request.path,
        "http_query": request.query_string,
        "http_headers": headers,
        "http_body": body_text[:4096],   # cap at 4 KB
        "http_user_agent": headers.get("User-Agent", ""),
        "attack_type": attack_type,
    }))

    return await handler(request)


# ──────────────────────────────────────────────────────────────
# Route handlers
# ──────────────────────────────────────────────────────────────
async def handle_env(request: web.Request) -> web.Response:
    return web.Response(body=FAKE_ENV, content_type="text/plain")

async def handle_git_config(request: web.Request) -> web.Response:
    return web.Response(body=FAKE_GIT_CONFIG, content_type="text/plain")

async def handle_wp_login(request: web.Request) -> web.Response:
    return web.Response(body=FAKE_WP_LOGIN, content_type="text/html")

async def handle_admin(request: web.Request) -> web.Response:
    return web.Response(body=FAKE_ADMIN_LOGIN, content_type="text/html", status=200)

async def handle_phpmyadmin(request: web.Request) -> web.Response:
    return web.Response(body=FAKE_PHPMYADMIN, content_type="text/html")

async def handle_actuator(request: web.Request) -> web.Response:
    return web.Response(body=FAKE_ACTUATOR, content_type="application/json")

async def handle_api_users(request: web.Request) -> web.Response:
    return web.Response(body=FAKE_API_USERS, content_type="application/json")

async def handle_config_php(request: web.Request) -> web.Response:
    return web.Response(body=FAKE_CONFIG_PHP, content_type="text/plain")

async def handle_console(request: web.Request) -> web.Response:
    body = b"<html><body><h2>Console</h2><p>Not available.</p></body></html>"
    return web.Response(body=body, content_type="text/html", status=403)

async def catch_all(request: web.Request) -> web.Response:
    return web.Response(text="Not Found", status=404)


# ──────────────────────────────────────────────────────────────
# App factory
# ──────────────────────────────────────────────────────────────
def make_app() -> web.Application:
    app = web.Application(middlewares=[log_and_tag])
    app.router.add_route("*", "/.env",              handle_env)
    app.router.add_route("*", "/.git/config",       handle_git_config)
    app.router.add_route("*", "/wp-login.php",      handle_wp_login)
    app.router.add_route("*", "/admin",             handle_admin)
    app.router.add_route("*", "/admin/",            handle_admin)
    app.router.add_route("*", "/admin/{tail:.*}",   handle_admin)
    app.router.add_route("*", "/phpmyadmin",        handle_phpmyadmin)
    app.router.add_route("*", "/phpmyadmin/",       handle_phpmyadmin)
    app.router.add_route("*", "/actuator",          handle_actuator)
    app.router.add_route("*", "/actuator/{tail:.*}",handle_actuator)
    app.router.add_route("*", "/api/v1/users",      handle_api_users)
    app.router.add_route("*", "/config.php",        handle_config_php)
    app.router.add_route("*", "/console",           handle_console)
    app.router.add_route("*", "/{tail:.*}",         catch_all)
    return app


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info(f"Starting HTTP honeypot on port {HTTP_PORT}…")
    web.run_app(make_app(), host="0.0.0.0", port=HTTP_PORT)
