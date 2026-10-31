# Architecture

AzureGuard records projects and releases, ingests normalized scanner reports, evaluates a deterministic risk policy, and exposes findings and decisions to clients. The existing React + TypeScript + Vite client remains in `frontend/`; a separate Angular + TypeScript client is in `frontend-angular/` so the existing app is preserved.

## Request flow

Angular calls the authenticated ASP.NET Core API. Controllers validate requests and use EF Core (`AppDbContext`) against SQL Server/Azure SQL. Release scan ingestion stores `ScanResult` and `ScanFinding` rows; `RiskPolicyEngine` applies deterministic local weights (critical 25, high 6, medium 2, low 0.25; capped at 100) and critical hard block. Failed scanners return `REVIEW_REQUIRED`. The .NET `PythonAiRemediationService` forwards sanitized finding metadata to the Python service; Python calls Azure OpenAI and returns structured guidance. AI cannot affect release decisions.

## Endpoints

Existing endpoints include `/api/auth/signup`, `/api/auth/login`, `/api/projects`, `/api/projects/{projectId}/releases`, nested release `scans`, `reports`, `dashboard`, `pipeline`, `approve`, `reject`, and `deploy`. New authenticated endpoints are `GET /api/releases/{releaseId}/findings?page=1&pageSize=50`, `POST /api/releases/{releaseId}/risk-evaluation`, and `POST /api/ai/remediation`. The .NET service forwards only scanner, finding ID, severity, file location, description and commit reference to internal Python `POST /api/remediation`. Both layers redact credentials and source-like descriptions.

## Components

The database layer uses EF Core with SQL Server and existing SQL scripts; Azure SQL requires a configured `ConnectionStrings__DefaultConnection`. Jenkins integration is implemented but requires Jenkins credentials and webhook secret. Gitleaks, Trivy, Checkov and SonarQube report parsing exists; Jenkins executes Gitleaks and Trivy. Git diff sensitive-configuration analysis is not implemented. Python uses the Azure OpenAI client with environment configuration, request timeout and bounded retries. Python unit tests mock the AI client; .NET tests mock the Python service contract. No real Azure OpenAI call has been verified.

## Local development

Copy `.env.example` to `.env` and replace placeholders with SQL credentials, a strong JWT key, and valid Azure OpenAI endpoint/key/deployment values. `docker compose up --build` starts SQL Server, API, internal Python AI service, and Angular UI. The existing database does not currently have automatic migrations or initialization in Compose; apply the SQL scripts or provision the schema separately before using API data endpoints. For direct local development, start Python with `python -m uvicorn app.main:app --app-dir ai-service --port 8000`, Angular with `cd frontend-angular; npm ci; npm start`, and the backend with `dotnet run --project backend/AzureGuard/AzureGuard`.

## Interview overview

Explain the persisted release and scan model, normalization by `ScannerReportParser`, and policy decision path through `ReleaseService` and `RiskPolicyEngine`. The score is an explicitly project-specific rule policy, not a recognized security standard. Azure OpenAI produces remediation guidance only. Jenkins upload uses HMAC validation for raw scanner reports.
