## Relevant Files

- `docker-compose.yml` - Docker compose configuration defining all 8 services.
- `.env.example` - Template for environment variables.
- `db/models.py` - Database models for events, IP profiles, credentials, campaigns, MITRE tags, and reports.
- `db/migrations/` - Alembic migrations for DB schema management.
- `api/main.py` - FastAPI entrypoint and event ingestion endpoints.
- `ssh-sensor/main.py` - Python SSH sensor simulating interactive shell.
- `http-sensor/main.py` - Python HTTP sensor exposing high-value endpoints and payload checking.
- `worker/main.py` - Async enrichment worker running AbuseIPDB, ip-api, MITRE mapping, and credential matching.
- `worker/mitre_mapping.json` - Static JSON config containing observed behavior mapping to MITRE Technique IDs.
- `scheduler/main.py` - Weekly cron scheduler for report generation.
- `dashboard/` - React dashboard application.
- `terraform/` - Terraform configuration for provisioning Azure VM, networking, and DNS.

### Notes

- Run python services inside their respective directories or docker containers.
- Unit tests should be placed alongside their modules (e.g. `api/tests/` or next to source files).
- Use `pytest` to run tests for Python components.

## Instructions for Completing Tasks

**IMPORTANT:** As you complete each task, you must check it off in this markdown file by changing `- [ ]` to `- [x]`. This helps track progress and ensures you don't skip any steps.

Example:
- `- [ ] 1.1 Read file` → `- [x] 1.1 Read file` (after completing)

Update the file after completing each sub-task, not just after completing an entire parent task.

## Tasks

- [x] 0.0 Create feature branch
  - [x] 0.1 Create and checkout a new branch for this feature (e.g., `git checkout -b feature/honeypot-intelligence-platform`)
- [x] 1.0 Setup Infrastructure and Database Migration
  - [x] 1.1 Create `docker-compose.yml` defining services: `db` (PostgreSQL), `cache` (Redis)
  - [x] 1.2 Create `.env.example` and set up database/cache connection strings
  - [x] 1.3 Initialize Alembic in the repository for database migrations
  - [x] 1.4 Design and implement the SQL models in `db/models.py` (events, ip_profiles, credentials, campaigns, mitre_tags, reports)
  - [x] 1.5 Create and execute the initial Alembic migration to build the database schema
- [x] 2.0 Implement Core Sensors and Backend Ingest API
  - [x] 2.1 Set up the FastAPI backend (`api/main.py`) with ingest endpoint (`POST /api/v1/events`)
  - [x] 2.2 Implement rate limiting (1000 events/min) on the ingest endpoint
  - [x] 2.3 Implement the SSH Honeypot Sensor using `asyncssh` to capture connection metadata (IP, port, user/pass, client fingerprint)
  - [x] 2.4 Add SSH interactive shell simulation (fake CLI logging command input, fake login percentage)
  - [x] 2.5 Implement the HTTP Honeypot Sensor using `aiohttp` to expose fake endpoints (`/admin`, `/wp-login.php`, etc.)
  - [x] 2.6 Implement HTTP attack signature matching (SQLi, XSS, traversal, cmd injection) and tag events accordingly
  - [x] 2.7 Ensure sensors send events to the backend ingest endpoint via Docker network isolation (`ingest` network only)
- [ ] 3.0 Develop Ingest & Enrichment Pipeline
  - [ ] 3.1 Build the background enrichment worker (`worker/main.py`) to consume raw events
  - [ ] 3.2 Implement IP reputation/geolocation lookup using AbuseIPDB (cache-first, rate-limit fallback) and `ip-api.com`
  - [ ] 3.3 Add Redis caching layer (24-hour TTL) for IP lookup queries
  - [ ] 3.4 Implement SSH credential classification against a common credential list
  - [ ] 3.5 Implement campaign detection logic (3+ IPs sharing credential list/UA/commands within 1 hour)
  - [ ] 3.6 Implement MITRE ATT&CK technique mapping using a static JSON configuration (`worker/mitre_mapping.json`)
  - [ ] 3.7 Ensure DB worker query safety using `FOR UPDATE SKIP LOCKED`
- [ ] 4.0 Build the SOC Dashboard Frontend
  - [ ] 4.1 Scaffold a React Single Page Application (SPA) with a dark theme and configure it for SOC monitors
  - [ ] 4.2 Set up state management and routing (using React/Vite/Next.js as requested or needed)
  - [ ] 4.3 Implement real-time feed updates using WebSockets/SSE or 30-second auto-refresh
  - [ ] 4.4 Build the Live Attack Feed, World Map (using Leaflet), and Attack Volume Timeline (using Recharts)
  - [ ] 4.5 Build Top Credentials, Top Attacking IPs, MITRE ATT&CK Heatmap, Campaign Tracker, and Sensor Health panels
  - [ ] 4.6 Implement global filtering (time range, sensor type, country)
  - [ ] 4.7 Implement the IP detail drawer showing full enrichment, events, timeline, and observed MITRE techniques
- [ ] 5.0 Implement Reporting & Automated Scheduler
  - [ ] 5.1 Create `scheduler/main.py` to trigger weekly report generation every Monday at 00:00 UTC
  - [ ] 5.2 Implement report compilation (event counts, IPs, campaigns, etc. and week-over-week comparisons)
  - [ ] 5.3 Implement LLM-assisted summary generation if OpenAI/Anthropic keys are configured, fallback to Jinja2 templates if not
  - [ ] 5.4 Export reports to PDF format and store them in PostgreSQL (accessible/downloadable from dashboard)
  - [ ] 5.5 Add manual report trigger button on the dashboard
- [ ] 6.0 Configure Cloud Infrastructure and Hardening
  - [ ] 6.1 Set up Terraform config for Azure (VM, networking, NSGs, DNS)
  - [ ] 6.2 Apply security hardening: isolate sensor containers from internal DB networks, drop capabilities for the SSH sensor
  - [ ] 6.3 Finalize README with architecture diagram, screenshots, setup instructions, and portfolio success metrics
  - [ ] 6.4 Write sample data exporter to include anonymized real attack data in the repository
