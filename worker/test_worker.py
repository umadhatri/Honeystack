import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
import json
from main import (
    get_ip_enrichment,
    classify_and_log_credential,
    tag_mitre_techniques,
    detect_and_assign_campaign,
    process_event
)

@pytest.mark.asyncio
@patch("main.httpx.AsyncClient")
async def test_get_ip_enrichment_cached(mock_client_class):
    mock_redis = AsyncMock()
    mock_redis.get.return_value = json.dumps({
        "ip": "1.1.1.1",
        "abuse_score": 15,
        "country": "Australia"
    })

    result = await get_ip_enrichment("1.1.1.1", mock_redis)
    
    assert result["ip"] == "1.1.1.1"
    assert result["abuse_score"] == 15
    assert result["country"] == "Australia"
    mock_redis.get.assert_called_with("ip_profile:1.1.1.1")
    assert not mock_client_class.called

@pytest.mark.asyncio
@patch("main.httpx.AsyncClient")
async def test_get_ip_enrichment_uncached(mock_client_class):
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None

    # Mock API responses
    mock_client = AsyncMock()
    mock_client_class.return_value.__aenter__.return_value = mock_client

    # First call: AbuseIPDB, Second call: ip-api.com
    # Set up mock response objects
    mock_resp_abuse = MagicMock()
    mock_resp_abuse.status_code = 200
    mock_resp_abuse.json.return_value = {"data": {"abuseConfidenceScore": 88, "totalReports": 5}}

    mock_resp_geo = MagicMock()
    mock_resp_geo.status_code = 200
    mock_resp_geo.json.return_value = {
        "status": "success",
        "country": "Germany",
        "countryCode": "DE",
        "city": "Berlin",
        "isp": "LocalISP",
        "as": "AS12345",
        "org": "LocalOrg"
    }

    mock_client.get.side_effect = [mock_resp_abuse, mock_resp_geo]

    # Patch API key
    with patch("main.ABUSEIPDB_API_KEY", "real_api_key"):
        result = await get_ip_enrichment("2.2.2.2", mock_redis)

    assert result["ip"] == "2.2.2.2"
    assert result["abuse_score"] == 88
    assert result["country"] == "Germany"
    mock_redis.setex.assert_called_once()

@pytest.mark.asyncio
async def test_classify_and_log_credential():
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.one_or_none.return_value = (10, 5) # ID=10, attempt_count=5
    mock_db.execute.return_value = mock_result
    event = {"ssh_username": "root", "ssh_password": "password123"}
    
    classification = await classify_and_log_credential(event, mock_db)
    assert classification == "rockyou_top_1000"
    
    # Verify UPDATE statement was run
    assert mock_db.execute.call_count == 2
    assert "UPDATE credentials" in mock_db.execute.call_args_list[1][0][0].text

    # 2. Test new custom credential logic
    mock_db.reset_mock()
    mock_result_custom = MagicMock()
    mock_result_custom.one_or_none.return_value = None
    mock_db.execute.return_value = mock_result_custom
    event_custom = {"ssh_username": "unknown_user_xyz", "ssh_password": "strange_password"}
    
    classification_custom = await classify_and_log_credential(event_custom, mock_db)
    assert classification_custom == "custom"
    
    # Verify INSERT statement was run
    assert mock_db.execute.call_count == 2
    assert "INSERT INTO credentials" in mock_db.execute.call_args_list[1][0][0].text

@pytest.mark.asyncio
async def test_tag_mitre_techniques():
    mock_db = AsyncMock()
    
    event = {
        "id": 42,
        "sensor_type": "SSH",
        "ssh_commands": ["xmrig -o pool.supportxmr.com"]
    }
    
    # Run tagger
    await tag_mitre_techniques(event, "custom", mock_db)
    
    # T1110.001 (guess attempt), T1059 (commands executed), T1496 (resource hijack miner)
    # The DB execute should be called for each matched rule insertion
    # Let's count calls to insert mitre_tags
    insert_calls = [c for c in mock_db.execute.call_args_list if "INSERT INTO mitre_tags" in c[0][0].text]
    assert len(insert_calls) >= 3

@pytest.mark.asyncio
async def test_detect_and_assign_campaign():
    mock_db = AsyncMock()
    
    mock_result = MagicMock()
    # Case 1: Campaign detected (3 distinct IPs)
    mock_result.all.return_value = [("1.1.1.1",), ("2.2.2.2",), ("3.3.3.3",)]
    # Mock campaign create return value
    mock_result.one_or_none.return_value = None  # no active campaign
    mock_result.scalar_one.return_value = 999   # newly created campaign ID
    mock_db.execute.return_value = mock_result
    
    event = {
        "sensor_type": "SSH",
        "ssh_username": "root",
        "ssh_password": "password123"
    }
    
    campaign_id = await detect_and_assign_campaign(event, mock_db)
    assert campaign_id == 999
