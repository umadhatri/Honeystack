# PRD: Honeypot Intelligence Platform
**Codename:** `honeystack`
**Author:** Umadhatri Durvasula
**Status:** Draft v1.0
**Last Updated:** June 2026

---

## 1. Introduction / Overview

### What is honeystack?
`honeystack` is a self-hosted, production-grade honeypot intelligence platform that deploys fake SSH and HTTP services to attract real-world attackers, captures and enriches their behavior, maps it to the MITRE ATT&CK framework, and surfaces actionable threat intelligence through a SOC-grade dashboard.

### The Problem It Solves
Most security side projects are either:
- Simulated (fake data, fake attacks, no real signal), or
- Shallow (just log collection with no analysis layer)

`honeystack` is neither. Within hours of deployment, real bots and attackers will probe it. Every connection is a real threat signal. The platform turns that raw noise into structured, analyst-ready intelligence — the same way a real threat intel team would.

### The Goal
Build a platform that:
1. Runs entirely on Docker Compose for local development
2. Can be deployed to any cloud (initially Azure Free Tier) with minimal changes
3. Produces a dashboard that would not look out of place in an actual SOC environment
4. Becomes a portfolio anchor that demonstrates: infrastructure depth, security engineering, data pipeline design, and full-stack delivery — in a single project

---

## 2. Goals

1. **Capture real attacker behavior** — Deploy SSH and HTTP honeypot sensors that attract and log live attack traffic from the public internet
2. **Enrich every event** — Automatically annotate each event with IP reputation, geolocation, ASN, and credential classification
3. **Map to MITRE ATT&CK** — Tag every observed attacker behavior to a MITRE technique ID automatically
4. **Deliver SOC-grade visibility** — A real-time dashboard with world map, attack timelines, credential analysis, and MITRE heatmap — everything a tier-1 analyst needs at a glance
5. **Generate threat intelligence reports** — Automated weekly summaries, LLM-assisted if an API key is configured, template-based if not
6. **Be fully reproducible** — Anyone can clone the repo, run `docker compose up`, and have the full platform running in under 5 minutes

---

## 3. User Stories

> The primary "user" of this platform is a security analyst or the builder themselves reviewing collected intelligence. There are no external end-users.

### As the platform operator:
- I want to stand up all sensors and backend services with a single command so I can focus on the security data, not infrastructure setup
- I want to see incoming attacks in real time on the dashboard so I can observe attacker behavior as it happens
- I want every captured event to be automatically enriched so I never have to manually look up an IP or credential
- I want weekly reports generated automatically so I have a structured intelligence artifact I can share or reference

### As a security analyst reviewing the dashboard:
- I want to see a live world map of attack origins so I can immediately understand the geographic distribution of threats
- I want to see the top credentials being tried so I can identify active brute-force campaigns
- I want to see MITRE ATT&CK technique coverage so I can understand what attacker behaviors are being observed
- I want to filter events by time range, sensor type, IP, or technique so I can investigate specific incidents
- I want to see per-IP attack timelines so I can distinguish automated scanners from deliberate human attackers

### As a recruiter or hiring manager reviewing the GitHub repo:
- I want to see a clear README with architecture diagram, live screenshots, and quick-start instructions so I can understand what was built without reading all the code
- I want to see real data captured by the platform (anonymized) so I know this wasn't built against simulated inputs

---

## 4. Functional Requirements

### 4.1 — SSH Honeypot Sensor
1. The system **must** run a fake SSH server on a configurable port (default: 22, fallback: 2222)
2. The sensor **must** accept all incoming connections and log: source IP, port, timestamp, attempted username, attempted password
3. The sensor **must** simulate a fake successful login for a configurable percentage of attempts (default: 5%) to observe post-login behavior
4. On fake successful login, the sensor **must** drop the attacker into a fake interactive shell that logs every command typed without executing anything on the real system
5. The sensor **must** fingerprint the SSH client version string and log it as part of the event
6. All events **must** be written to the central PostgreSQL database within 1 second of capture

### 4.2 — HTTP Honeypot Sensor
7. The system **must** run a fake HTTP server on port 80 (and optionally 443 with self-signed cert)
8. The HTTP sensor **must** expose a set of high-value fake endpoints that real attackers commonly target:
   - `/admin`, `/wp-login.php`, `/phpmyadmin`, `/.env`, `/config.php`, `/.git/config`, `/api/v1/users`, `/actuator`, `/console`
9. For every request, the sensor **must** log: source IP, HTTP method, path, query string, all headers, request body (if present), user agent, and timestamp
10. The sensor **must** return realistic-looking fake responses (e.g., a fake WordPress login page, a fake `.env` file with dummy credentials) to encourage attackers to interact further
11. The sensor **must** detect and log common attack payloads: SQL injection strings, XSS payloads, path traversal attempts, and command injection patterns
12. All HTTP events **must** be tagged with the attack type detected (SQLi, XSS, path traversal, scan, credential stuffing, etc.)

### 4.3 — Ingest & Enrichment Pipeline
13. The system **must** run an async enrichment worker that processes every raw event within 5 seconds of capture
14. For every unique source IP, the enrichment worker **must** query:
    - **AbuseIPDB** — abuse confidence score and report count (free tier API key required)
    - **ip-api.com** — country, city, ISP, ASN, and organization (free, no key required)
15. IP enrichment results **must** be cached in Redis with a 24-hour TTL to avoid redundant API calls
16. The system **must** classify every SSH credential pair against a known brute-force wordlist (RockYou top 1000, SecLists common credentials) and flag matches
17. The system **must** detect coordinated campaigns: if 3+ IPs share the same credential list, user agent, or command sequence within a 1-hour window, they **must** be tagged as belonging to the same campaign
18. Every event **must** be tagged with one or more MITRE ATT&CK technique IDs based on the following mapping:

| Observed Behavior | MITRE Technique |
|---|---|
| SSH credential brute force | T1110.001 — Password Guessing |
| Credential stuffing (known breach list) | T1110.004 — Credential Stuffing |
| `.env` / config file probing | T1552.001 — Credentials in Files |
| Command execution in fake shell | T1059 — Command and Scripting Interpreter |
| Crypto miner deployment attempt | T1496 — Resource Hijacking |
| Port/path scanning behavior | T1595.002 — Vulnerability Scanning |
| Git config / source code probing | T1213 — Data from Information Repositories |
| Admin panel brute force | T1078 — Valid Accounts |

### 4.4 — Data Storage
19. The system **must** use PostgreSQL as the primary data store with the following core tables:
    - `events` — raw sensor events (all types)
    - `ip_profiles` — enriched IP metadata and reputation scores
    - `credentials` — observed username/password pairs with classification
    - `campaigns` — grouped coordinated attack campaigns
    - `mitre_tags` — event-to-technique mappings
    - `reports` — generated weekly intelligence reports
20. The database schema **must** be managed via Alembic migrations so the schema is version-controlled and reproducible
21. Redis **must** be used for: IP enrichment cache, real-time event counters, and live dashboard feed (pub/sub)

### 4.5 — SOC Dashboard
22. The dashboard **must** be a React single-page application served via Nginx
23. The dashboard **must** include the following panels, all visible on a single 1080p screen without scrolling (SOC wall-display ready):

| Panel | What it shows |
|---|---|
| **Live Attack Feed** | Real-time scrolling log of incoming events with type, IP, country flag, and technique tag |
| **World Map** | Choropleth or dot map showing attack origin countries, colored by volume |
| **Attack Volume Timeline** | Line/bar chart of events per hour over the last 7 days, split by sensor type |
| **Top Credentials** | Ranked table of most-attempted username/password pairs |
| **Top Attacking IPs** | Table with IP, country, ASN, abuse score, event count, and first/last seen |
| **MITRE ATT&CK Heatmap** | ATT&CK navigator-style grid showing which techniques have been observed |
| **Campaign Tracker** | List of detected coordinated campaigns with IP count, start time, and shared indicators |
| **Sensor Health** | Status indicators for SSH and HTTP sensors (up/down, events/min, last event time) |

24. The dashboard **must** auto-refresh every 30 seconds without a full page reload
25. The dashboard **must** support filtering the entire view by: time range (1h, 6h, 24h, 7d, 30d), sensor type (SSH / HTTP / All), and country
26. Clicking any IP in any panel **must** open an IP detail drawer showing: full enrichment data, all events from that IP, timeline, and MITRE techniques observed
27. The dashboard color scheme **must** use a dark theme consistent with SOC environments (dark background, high-contrast status colors: green/amber/red)
28. The dashboard **must** be fully functional on both a standard monitor and a wide-format SOC display (16:9 and 21:9)

### 4.6 — Weekly Threat Intelligence Report
29. The system **must** auto-generate a weekly report every Monday at 00:00 UTC covering the previous 7 days
30. The report **must** include: total event count, unique IPs, top 10 credentials, top 5 attacking countries, new campaigns detected, MITRE techniques observed, and week-over-week comparison
31. If an LLM API key is configured (OpenAI or Anthropic), the system **must** use it to generate a natural language executive summary and key findings section
32. If no API key is configured, the system **must** fall back to a structured template-based report that produces the same sections using rule-based text generation
33. Reports **must** be stored in PostgreSQL and accessible from the dashboard as downloadable PDFs
34. The report generation **must** be triggerable manually via a dashboard button in addition to the automated schedule

### 4.7 — Infrastructure & Deployment
35. The entire platform **must** run with `docker compose up` — no manual steps beyond copying a `.env` file
36. The `docker-compose.yml` **must** define the following services: `ssh-sensor`, `http-sensor`, `api` (FastAPI backend), `worker` (enrichment pipeline), `db` (PostgreSQL), `cache` (Redis), `dashboard` (React + Nginx), `scheduler` (report generation)
37. The platform **must** include a single `.env.example` file documenting every required and optional environment variable
38. Terraform configuration **must** be provided for Azure deployment (the primary cloud target), defining: VM, networking, NSGs, and DNS
39. The SSH sensor container **must** run with the minimum required Linux capabilities — no privileged mode
40. All secrets (API keys, DB passwords) **must** be passed via environment variables, never hardcoded

---

## 5. Non-Goals (Out of Scope for v1)

- **Active defense or deception** — honeystack does not attempt to hack back, trace attackers, or actively interfere with their operations
- **Email alerting** — no alert emails or PagerDuty integrations in v1; dashboard visibility is sufficient
- **Multi-user auth on dashboard** — the dashboard is a single-operator tool; no login screen in v1
- **FTP, Telnet, or RDP honeypots** — SSH and HTTP sensors only in v1; additional protocols are a v2 stretch goal
- **Mobile-responsive dashboard** — SOC-display and desktop only; mobile is not a target form factor
- **Compliance reporting** — no SOC2, ISO27001, or regulatory report formats
- **Paid API dependencies** — everything must work on free tiers; AbuseIPDB free tier (1000 checks/day) is the only API with a rate limit concern

---

## 6. Design Considerations

### Dashboard Design Principles
- **Dark theme, always.** No light mode. Background: `#0d1117` (GitHub dark). Panel backgrounds: `#161b22`. Accent: `#58a6ff` (blue) for neutral, `#3fb950` (green) for healthy, `#d29922` (amber) for warning, `#f85149` (red) for critical.
- **Density over whitespace.** This is a SOC tool. Every pixel should carry information. No hero sections, no marketing copy, no empty space.
- **Real-time feel.** The live attack feed should feel alive. Use subtle pulse animations on new events. The world map should animate new attack dots appearing.
- **Data tables over charts where precision matters.** Credentials and IP lists are tables. Volume over time is a chart. Don't use a pie chart anywhere.

### Tech Stack Decisions
| Layer | Choice | Reason |
|---|---|---|
| Sensors | Python (asyncssh, aiohttp) | Async, lightweight, easy to fake protocol behavior |
| Backend API | FastAPI | Already in Uma's stack, async, auto-docs |
| Enrichment | Python async workers | Celery is overkill; simple asyncio task queue is enough |
| Database | PostgreSQL | Already in Uma's stack; FOR UPDATE SKIP LOCKED for worker safety |
| Cache | Redis | Already in Uma's stack; pub/sub for live dashboard feed |
| Dashboard | React + Recharts + Leaflet | Recharts for timelines/heatmap, Leaflet for world map |
| Deployment | Docker Compose → Azure VM | Progressive complexity; compose first, cloud second |
| IaC | Terraform | Already in Uma's stack |

---

## 7. Technical Considerations

### Security of the Platform Itself
- The SSH and HTTP sensor containers **must** be isolated from the API and database containers via Docker network segmentation — sensors write to a dedicated `ingest` network, never directly to the DB
- Sensors **must** communicate with the backend only via an internal FastAPI ingest endpoint, not direct DB access
- The FastAPI backend and dashboard **must never** be exposed on the same network interface as the sensors
- Rate limit the ingest endpoint (1000 events/min) to prevent a flood attack from overwhelming the backend

### AbuseIPDB Rate Limits
- Free tier allows 1,000 IP checks per day
- Redis cache with 24-hour TTL per IP will prevent redundant checks
- Implement a cache-first lookup: check Redis before calling the API
- If the daily limit is hit, log a warning and skip enrichment for that event (don't block ingestion)

### PostgreSQL Worker Safety
- Use `FOR UPDATE SKIP LOCKED` on the enrichment worker queue (Uma has already implemented this pattern at CySTAR — apply the same approach here)
- This allows multiple enrichment worker replicas to run safely in parallel without event duplication

### MITRE ATT&CK Mapping
- Embed the mapping table as a static JSON config file, not hardcoded in Python
- This makes it easy to add new technique mappings without code changes
- Reference the official MITRE ATT&CK STIX data for technique IDs and names

### LLM Report Generation (Optional)
- Check for `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in environment at report generation time
- If present: call the API with a structured prompt containing the week's statistics and ask for an executive summary
- If absent: use a Jinja2 template that generates grammatically correct prose from the same statistics
- The template fallback must produce a report indistinguishable in structure from the LLM version

---

## 8. Success Metrics

Since this is a portfolio project, success is measured across two dimensions:

### Technical Success
- [ ] Platform starts with `docker compose up` in under 5 minutes on a clean machine
- [ ] SSH and HTTP sensors capture real attack traffic within 2 hours of exposure on a public IP
- [ ] 100% of captured events are enriched with IP reputation and geolocation data
- [ ] 100% of events are tagged with at least one MITRE ATT&CK technique
- [ ] Dashboard renders all 8 panels on a single 1080p screen without scrolling
- [ ] Weekly report generates automatically and is accessible from the dashboard
- [ ] Platform runs continuously for 30 days without manual intervention

### Portfolio Success
- [ ] GitHub README includes: project description, architecture diagram, live screenshots with real attack data, quick-start instructions, and a "what I learned" section
- [ ] At least one LinkedIn post with a dashboard screenshot and anonymized real attack data, showing week-over-week threat trends
- [ ] Resume bullet accurately describes the platform with at least 2 concrete metrics from real captured data (e.g., "captured 10,000+ events from 500+ unique IPs in 30 days")
- [ ] Any engineer can clone the repo, read the README, and understand the architecture in under 10 minutes

---

## 9. Implementation Phases

### Phase 1 — Core Sensors + Storage (Week 1–2)
- SSH honeypot sensor logging to PostgreSQL
- HTTP honeypot sensor with fake endpoints
- Docker Compose setup with all services defined
- Basic FastAPI ingest endpoint
- Alembic schema migrations

### Phase 2 — Enrichment Pipeline (Week 3)
- IP enrichment worker (AbuseIPDB + ip-api.com)
- Redis caching layer
- Credential classification against wordlists
- MITRE ATT&CK auto-tagging
- Campaign detection logic

### Phase 3 — SOC Dashboard (Week 4–5)
- React app scaffold with dark theme
- All 8 dashboard panels
- Real-time feed via WebSocket or SSE
- World map with Leaflet
- IP detail drawer
- Time range and filter controls

### Phase 4 — Reports + Polish (Week 6)
- Weekly report generator (template + optional LLM)
- PDF export
- Terraform config for Azure deployment
- README with architecture diagram and screenshots
- Security hardening review

### Phase 5 — Live Deployment + Data Collection (Ongoing)
- Deploy to Azure free-tier VM
- Expose SSH sensor to public internet
- Collect 30 days of real attack data
- Update README with real metrics
- Write LinkedIn post

---

## 10. Open Questions

1. **Fake shell depth:** How realistic should the fake SSH shell be? Should it respond to `ls`, `cat`, `whoami` with fake outputs, or drop the connection after logging the first command?
   - *Recommendation: Respond to top-20 common post-compromise commands with fake outputs. Staying connected longer captures more attacker behavior.*

2. **Campaign detection threshold:** 3 IPs sharing indicators within 1 hour is a starting heuristic. This may produce false positives or miss slow campaigns. Should this be configurable via environment variable?
   - *Recommendation: Yes — make threshold and time window configurable in `.env`*

3. **Azure deployment topology:** Should the SSH sensor run on the same VM as the backend (separated by Docker networks) or on a separate cheap VM for true network isolation?
   - *Recommendation: Same VM for v1 (cost), separate VM as a stretch goal for v2*

4. **Data retention:** How long should raw events be kept in PostgreSQL before archiving or deletion?
   - *Recommendation: 90 days rolling, configurable via environment variable*

5. **GitHub data ethics:** Real attacker IPs will be in the database. Should the public GitHub repo include a sample dataset with IPs anonymized, or link to a live read-only dashboard instead?
   - *Recommendation: Include anonymized sample data in repo + link to live dashboard if deployed*

---

## Appendix: Resume Bullet (Target)

Once the platform is live and has collected 30 days of data, the resume bullet should read:

> *"Built and deployed honeystack, a production-grade honeypot intelligence platform on Azure that captured live attack traffic from X+ unique IPs across Y countries, auto-mapped attacker behavior to MITRE ATT&CK techniques, and surfaced threat intelligence through a SOC-grade real-time dashboard and automated weekly reports"*

Fill in X and Y with real numbers from your deployment. Those numbers are your credibility.
