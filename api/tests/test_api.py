import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
from main import app, get_db

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "honeystack-api"}

@pytest.mark.asyncio
async def test_ingest_event():
    # Create a mock database session
    mock_db = AsyncMock()
    
    # Mock result of db.execute returning a mock scalar_one()
    mock_result = MagicMock()
    mock_result.scalar_one.return_value = 42
    mock_db.execute.return_value = mock_result

    # Override get_db dependency
    app.dependency_overrides[get_db] = lambda: mock_db

    payload = {
        "sensor_type": "SSH",
        "source_ip": "8.8.8.8",
        "source_port": 12345,
        "ssh_username": "root",
        "ssh_password": "password123",
        "ssh_client_version": "SSH-2.0-OpenSSH_8.2",
        "ssh_commands": ["ls", "whoami"]
    }

    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 201
    assert response.json() == {"id": 42, "status": "accepted"}
    assert mock_db.execute.called
    assert mock_db.commit.called

    # Clean up dependency overrides
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_list_events():
    mock_db = AsyncMock()
    mock_result = MagicMock()
    # Mock mapping result returning a list of dicts
    mock_result.mappings.return_value.all.return_value = [
        {
            "id": 1,
            "timestamp": "2026-06-29T12:00:00",
            "sensor_type": "SSH",
            "source_ip": "1.2.3.4",
            "source_port": 22,
            "ssh_username": "admin",
            "ssh_password": "password",
            "http_method": None,
            "http_path": None,
            "attack_type": None
        }
    ]
    mock_db.execute.return_value = mock_result
    app.dependency_overrides[get_db] = lambda: mock_db

    response = client.get("/api/v1/events?limit=10")
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 1
    assert events[0]["source_ip"] == "1.2.3.4"

    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_stats():
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.mappings.return_value.one.return_value = {
        "total_events": 100,
        "unique_ips": 5,
        "ssh_events": 60,
        "http_events": 40,
        "last_event": "2026-06-29T12:00:00"
    }
    mock_db.execute.return_value = mock_result
    app.dependency_overrides[get_db] = lambda: mock_db

    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] == 100
    assert data["unique_ips"] == 5

    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_top_credentials():
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.mappings.return_value.all.return_value = [
        {"ssh_username": "root", "ssh_password": "password", "attempts": 10}
    ]
    mock_db.execute.return_value = mock_result
    app.dependency_overrides[get_db] = lambda: mock_db

    response = client.get("/api/v1/top-credentials")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["ssh_username"] == "root"

    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_ip_detail():
    mock_db = AsyncMock()
    
    # We execute multiple statements:
    # 1. Profile select
    # 2. Events select
    # 3. Mitre tags select
    mock_profile_result = MagicMock()
    mock_profile_result.mappings.return_value.one_or_none.return_value = {
        "ip": "1.2.3.4",
        "abuse_score": 10,
        "country": "United States",
        "city": "Seattle"
    }
    
    mock_events_result = MagicMock()
    mock_events_result.mappings.return_value.all.return_value = [
        {
            "id": 1,
            "timestamp": "2026-06-29T12:00:00",
            "sensor_type": "HTTP",
            "source_port": 80,
            "ssh_username": None,
            "ssh_password": None,
            "http_method": "GET",
            "http_path": "/wp-login.php",
            "attack_type": "scan"
        }
    ]
    
    mock_mitre_result = MagicMock()
    mock_mitre_result.mappings.return_value.all.return_value = [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}
    ]
    
    mock_db.execute.side_effect = [
        mock_profile_result,
        mock_events_result,
        mock_mitre_result
    ]
    
    app.dependency_overrides[get_db] = lambda: mock_db

    response = client.get("/api/v1/ip/1.2.3.4")
    assert response.status_code == 200
    data = response.json()
    assert data["ip"] == "1.2.3.4"
    assert data["profile"]["abuse_score"] == 10
    assert len(data["events"]) == 1
    assert data["mitre_techniques"][0]["technique_id"] == "T1190"

    app.dependency_overrides.clear()
