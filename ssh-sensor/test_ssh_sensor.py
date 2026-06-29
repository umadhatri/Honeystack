import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import random
from main import HoneypotSSHServer, FakeShellSession

def test_begin_auth():
    server = HoneypotSSHServer()
    assert server.begin_auth("root") is True

@pytest.mark.asyncio
@patch("main.submit_event", new_callable=AsyncMock)
async def test_validate_password(mock_submit):
    server = HoneypotSSHServer()
    server._peername = ("1.2.3.4", 5555)
    server._client_version = "SSH-2.0-OpenSSH_8.2p1"

    # Test login success case
    with patch("random.random", return_value=0.01):
        # With LOGIN_PERCENTAGE default 0.05, 0.01 should be a success
        success = server.validate_password("root", "admin123")
        assert success is True
    
    # Test login failure case
    with patch("random.random", return_value=0.99):
        # 0.99 should fail
        success = server.validate_password("root", "wrongpass")
        assert success is False

    # Check that events were submitted with the correct payload
    assert mock_submit.call_count == 2
    first_call_args = mock_submit.call_args_list[0][0][0]
    assert first_call_args["sensor_type"] == "SSH"
    assert first_call_args["source_ip"] == "1.2.3.4"
    assert first_call_args["source_port"] == 5555
    assert first_call_args["ssh_username"] == "root"
    assert first_call_args["ssh_password"] == "admin123"
    assert first_call_args["ssh_client_version"] == "SSH-2.0-OpenSSH_8.2p1"

@pytest.mark.asyncio
@patch("main.submit_event", new_callable=AsyncMock)
async def test_fake_shell_session(mock_submit):
    mock_process = MagicMock()
    # Mock process.stdin as an async generator
    async def mock_stdin_gen():
        yield "ls\n"
        yield "whoami\n"
        yield "exit\n"

    mock_process.stdin = mock_stdin_gen()
    mock_process.stdout = MagicMock()

    session = FakeShellSession(mock_process, "1.2.3.4", "root")
    await session.run()

    # Verify stdout was written to
    assert mock_process.stdout.write.called
    # Verify the commands list captured
    assert session.commands == ["ls", "whoami", "exit"]
    # Verify process exit was called
    mock_process.exit.assert_called_with(0)

    # Verify event was submitted upon shell exit
    mock_submit.assert_called_once()
    payload = mock_submit.call_args[0][0]
    assert payload["sensor_type"] == "SSH"
    assert payload["source_ip"] == "1.2.3.4"
    assert payload["ssh_username"] == "root"
    assert payload["ssh_commands"] == ["ls", "whoami", "exit"]
