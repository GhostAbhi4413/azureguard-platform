<<<<<<< HEAD
# AzureGuard

AzureGuard is a release risk tracking project with an ASP.NET Core API, SQL Server data model, an existing React client, and a separate Angular/TypeScript dashboard. It ingests scanner findings and applies deterministic release policy rules.

See [architecture](docs/ARCHITECTURE.md), [implementation status](docs/IMPLEMENTATION_STATUS.md), and [security design](docs/SECURITY_DESIGN.md) for scope and limitations.

## Run locally

Copy `.env.example` to `.env`, replace local placeholders, then run `docker compose up --build`. The SQL schema must be applied separately using the scripts in `backend/database`; Compose does not run migrations. For direct development, use `npm ci && npm run dev` in `frontend`, `dotnet run --project backend/AzureGuard/AzureGuard` for the API, and `python -m uvicorn app.main:app --app-dir ai-service --reload --port 8000` for AI.

Configure `ConnectionStrings__DefaultConnection`, `Jwt__Key`, and (for live AI) `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, and `AZURE_OPENAI_DEPLOYMENT` through environment variables or secret storage. AI integration has not been tested with live credentials.

## Verification commands

```powershell
dotnet restore backend/AzureGuard/AzureGuard.sln --configfile backend/NuGet.Config
dotnet build backend/AzureGuard/AzureGuard.sln --configuration Release --no-restore
npm ci --prefix frontend
npm run build --prefix frontend
python -m pip install -r ai-service/requirements.txt
python -m compileall ai-service/app
python -m pytest ai-service/tests
docker compose config
```

GitHub Actions runs API build, React and Angular builds, Python tests, Gitleaks and Trivy on pull requests and pushes to `main`. To build Angular locally run `npm install && npm run build` in `frontend-angular`. Required status checks and branch protection must be configured in GitHub separately. See implementation status for components that remain planned or unverified.
=======
# AzureGuard Platform

AzureGuard is an automated DevSecOps platform, secret interception gate, and agent-assisted CI/CD security engine. Designed to safeguard modern cloud and AI architectures, it detects exposed LLM keys, cloud secrets, and credential leaks before code reaches production.

The platform is developed and maintained using **Spec-Driven Agentic Engineering workflows**—orchestrating AI coding agents across decoupled full-stack services with strict review gates and automated verification suites.

---

## Architecture & Tech Stack

- **Core Security Engine:** Python, Shannon entropy analysis, custom regex heuristics, and HMAC-SHA256 signature verification.
- **Backend & APIs:** Python (FastAPI/Flask) and .NET / ASP.NET Core REST APIs with relational data schemas and token parsing pipelines.
- **Frontend & Dashboard:** Modern responsive dashboard (React / Next.js / TypeScript) for audit trail monitoring, severity filtering, and real-time alerts.
- **Cloud & CI/CD Pipelines:** GitHub Actions workflows and Windows/Linux runner pipelines (`Jenkinsfile`) targeting enterprise Azure deployments.
- **Testing & Verification:** Comprehensive unit tests, integration contracts, and regression suites verifying scanner accuracy and zero-bypass security.

---

## Agentic Development Workflow

This codebase is built using parallel AI agent orchestration (Claude Code, Cursor, Copilot, and Codex) following strict engineering protocols:

- **Spec-Driven Implementation:** Features and patches originate from structured written specs containing defined acceptance criteria and edge-case test expectations before agent execution.
- **Isolated Multi-Session Worktrees:** Agent tasks execute in parallel on dedicated feature branches and Git worktrees to prevent overlapping diffs and maintain clean commit history.
- **Context & Memory Engineering (`AGENTS.md`):** Maintained an active `AGENTS.md` ruleset documenting architectural patterns, schema contracts, and boundary constraints to eliminate repeated agent hallucinations.
- **Human-in-the-Loop Diff Reviews:** Every agent-generated diff undergoes manual verification for tenant isolation, authentication/authorization checks, input sanitization, performance bottlenecks, and secrets hygiene prior to merging.
- **Test-First Verification:** Agents must write deterministic tests that fail on regressions and pass strictly when the acceptance criteria are met.

---

## Key Features

- **Multi-Model Secret Detection:** Dedicated scanner signatures for OpenAI, Google Gemini, Azure OpenAI, AWS, and generic cloud authorization credentials.
- **Automated CI/CD Quality Gate:** Halts pull requests and builds when high-entropy tokens or hardcoded secrets violate baseline compliance thresholds.
- **HMAC Audit Log Verification:** Implements HMAC-SHA256 signing for scanner outputs to ensure scan integrity between build runners and central audit dashboards.
- **Structured Compliance Outputs:** Emits standardized, machine-readable JSON reports detailing file locations, line indices, entropy metrics, and suggested remediations.
- **Containerized Build Integration:** Packaged into lightweight Docker containers for plug-and-play execution across local workstations and cloud agents.

---

## Project Structure

```text
azureguard-platform/
├── .github/workflows/      # Automated GitHub Actions scanning & build gates
├── backend/                # Scanner core, API services, and HMAC report verification
├── frontend/               # Full-stack monitoring dashboard and audit log explorer
├── tools/                  # Verification utilities, diagnostic scripts, and helper tools
├── AGENTS.md               # Context rules, coding standards, and prompt constraints for AI agents
├── Jenkinsfile             # Declarative pipeline script for automated CI/CD runners
├── PROJECT_STATUS.md       # Development roadmap, milestones, and active tasks
└── README.md               # Platform documentation and architecture specs
>>>>>>> 8a8a1d7931cc9b8f245f123b04d6620ebe1be51e
