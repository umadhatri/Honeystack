"""
honeystack – SSH Honeypot Sensor
Uses asyncssh to run a fake SSH server that logs credentials and post-login shell commands.
"""
import asyncio
import os
import random
import logging
import socket
from datetime import datetime, timezone

import asyncssh
import httpx
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────
API_URL            = os.getenv("API_URL", "http://api:8000/api/v1/events")
SSH_PORT           = int(os.getenv("SSH_PORT", "2222"))
LOGIN_PERCENTAGE   = float(os.getenv("SHELL_LOGIN_PERCENTAGE", "0.05"))

# ──────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("honeystack.ssh-sensor")

# ──────────────────────────────────────────────────────────────
# Fake interactive shell responses
# ──────────────────────────────────────────────────────────────
FAKE_HOSTNAME = "ubuntu-server"
FAKE_USERNAME = "root"

FAKE_RESPONSES: dict[str, str] = {
    "ls":      "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n",
    "ls -la":  "total 64\r\ndrwxr-xr-x 18 root root 4096 Jan  1 00:00 .\r\ndrwxr-xr-x 18 root root 4096 Jan  1 00:00 ..\r\n",
    "pwd":     "/root\r\n",
    "whoami":  "root\r\n",
    "id":      "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "uname -a":"Linux ubuntu-server 5.15.0-92-generic #102-Ubuntu SMP Wed Jan 10 09:33:48 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\r\n",
    "uname":   "Linux\r\n",
    "hostname":"ubuntu-server\r\n",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n",
    "cat /etc/shadow": "root:$6$rounds=5000$saltsalt$hashedhashhashedhash:19000:0:99999:7:::\r\n",
    "ifconfig":"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.4  netmask 255.255.255.0  broadcast 10.0.0.255\r\n",
    "ip addr": "1: lo: <LOOPBACK,UP,LOWER_UP>\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\r\n    inet 10.0.0.4/24\r\n",
    "netstat -tuln": "Active Internet connections (only servers)\r\nProto Recv-Q Send-Q Local Address  Foreign Address State\r\ntcp  0  0 0.0.0.0:22  0.0.0.0:* LISTEN\r\n",
    "ps aux":  "USER       PID %CPU %MEM COMMAND\r\nroot         1  0.0  0.1 /sbin/init\r\nroot       220  0.0  0.1 sshd\r\n",
    "ps":      "  PID TTY          TIME CMD\r\n 1234 pts/0    00:00:00 bash\r\n",
    "env":     "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\nHOME=/root\r\nUSER=root\r\n",
    "history": "    1  ls\r\n    2  whoami\r\n    3  cat /etc/passwd\r\n",
    "crontab -l": "no crontab for root\r\n",
    "df -h":   "Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/sda1        50G   12G   35G  26% /\r\n",
    "free -m": "              total        used        free\r\nMem:           7982        1024        6958\r\n",
    "wget":    "bash: wget: not found\r\n",
    "curl":    "bash: curl: command not found\r\n",
    "python3": "Python 3.10.12\r\n",
    "python":  "bash: python: command not found\r\n",
    "exit":    "",
    "logout":  "",
}

DEFAULT_RESPONSE = "bash: {cmd}: command not found\r\n"
PROMPT           = f"{FAKE_USERNAME}@{FAKE_HOSTNAME}:~# "


# ──────────────────────────────────────────────────────────────
# Post-event submission
# ──────────────────────────────────────────────────────────────
async def submit_event(payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(API_URL, json=payload)
            if resp.status_code != 201:
                logger.warning(f"API returned {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logger.error(f"Failed to submit event: {exc}")


# ──────────────────────────────────────────────────────────────
# Fake interactive shell session
# ──────────────────────────────────────────────────────────────
class FakeShellSession:
    def __init__(self, process: asyncssh.SSHServerProcess, source_ip: str, username: str):
        self.process   = process
        self.source_ip = source_ip
        self.username  = username
        self.commands: list[str] = []

    async def run(self):
        self.process.stdout.write(f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-92-generic x86_64)\r\n\r\n")
        self.process.stdout.write(PROMPT)

        try:
            async for line in self.process.stdin:
                cmd = line.rstrip("\r\n").strip()
                if not cmd:
                    self.process.stdout.write(PROMPT)
                    continue

                self.commands.append(cmd)
                logger.info(f"[SHELL] {self.source_ip} cmd: {cmd!r}")

                # look up response, base key = full cmd then just the first word
                response = FAKE_RESPONSES.get(cmd)
                if response is None:
                    response = FAKE_RESPONSES.get(cmd.split()[0] if cmd.split() else cmd)
                if response is None:
                    response = DEFAULT_RESPONSE.format(cmd=cmd.split()[0] if cmd.split() else cmd)

                if cmd in ("exit", "logout"):
                    self.process.stdout.write("logout\r\n")
                    break

                self.process.stdout.write(response + PROMPT)

        except asyncssh.BreakReceived:
            pass
        except Exception as exc:
            logger.debug(f"Shell session error: {exc}")
        finally:
            # Ship the full shell session as one event
            await submit_event({
                "sensor_type": "SSH",
                "source_ip": self.source_ip,
                "source_port": 0,
                "ssh_username": self.username,
                "ssh_commands": self.commands,
            })
            self.process.exit(0)


# ──────────────────────────────────────────────────────────────
# asyncssh server
# ──────────────────────────────────────────────────────────────
class HoneypotSSHServer(asyncssh.SSHServer):
    """One instance per incoming connection."""

    def __init__(self):
        self._username: str = ""
        self._password: str = ""
        self._peername: tuple = ("0.0.0.0", 0)
        self._client_version: str = ""

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        self._peername = peer
        # asyncssh exposes client_version after key exchange
        self._client_version = conn.get_extra_info("client_version", "") or ""
        logger.info(f"[CONNECT] {peer[0]}:{peer[1]}  client={self._client_version!r}")

    def begin_auth(self, username: str) -> bool:
        self._username = username
        return True  # require auth

    def password_auth_requested(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self._password = password
        ip, port = self._peername

        # Always accept the fake-login percentage of attempts
        fake_login = random.random() < LOGIN_PERCENTAGE

        logger.info(
            f"[AUTH] {ip}:{port} user={username!r} pass={password!r} "
            f"fake_login={fake_login}"
        )

        # Fire-and-forget credential event (commands added later on shell exit)
        asyncio.ensure_future(
            submit_event({
                "sensor_type": "SSH",
                "source_ip": ip,
                "source_port": port,
                "ssh_username": username,
                "ssh_password": password,
                "ssh_client_version": self._client_version,
            })
        )

        return fake_login


async def handle_client(process: asyncssh.SSHServerProcess):
    """Called when a successfully-authenticated client requests a shell."""
    conn   = process.get_extra_info("connection")
    peer   = conn.get_extra_info("peername") or ("0.0.0.0", 0)
    username = process.get_extra_info("username", "unknown")

    session = FakeShellSession(process, peer[0], username)
    await session.run()


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────
async def main():
    logger.info(f"Starting SSH honeypot on port {SSH_PORT}…")

    # Generate a fresh host key on startup (ephemeral, not stored)
    host_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)

    await asyncssh.create_server(
        HoneypotSSHServer,
        "",
        SSH_PORT,
        server_host_keys=[host_key],
        process_factory=handle_client,
        server_version="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        allow_pty=True,
    )

    logger.info(f"SSH honeypot listening on port {SSH_PORT}. Ctrl+C to stop.")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
