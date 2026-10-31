# Architecture

AzureGuard records projects and releases, ingests normalized scanner reports, evaluates a deterministic risk policy, and exposes findings and decisions to clients. The existing React + TypeScript + Vite client remains in `frontend/`; a separate Angular + TypeScript client is in `frontend-angular/` so the existing app is preserved.

## Request flow

The client calls the authenticated ASP.NET Core API. Controllers validate requests and use EF Core (`AppDbContext`) against SQL Server/Azure SQL. Release scan ingestion stores `ScanResult` and `ScanFinding` rows; `RiskPolicyEngine` applies deterministic local weights (critical 25, high 6, medium 2, low 0.25; capped at 100) and critical hard block. Failed scanners return manual review. AI is a separate advisory endpoint proxied by the API to FastAPI; it cannot affect release decisions.

## Endpoints

Existing endpoints include `/api/auth/signup`, `/api/auth/login`, `/api/projects`, `/api/projects/{projectId}/releases`, nested release `scans`, `reports`, `dashboard`, `pipeline`, `approve`, `reject`, and `deploy`. New authenticated endpoints are `GET /api/releases/{releaseId}/findings?page=1&pageSize=50`, `POST /api/releases/{releaseId}/risk-evaluation`, and `POST /api/ai/remediation`. AI forwards only scanner, finding ID, severity, file location, description and commit reference to `POST /api/remediation` on FastAPI. The request DTO excludes source-code and credential fields.

## Components

The database layer uses EF Core with SQL Server and existing SQL scripts; Azure SQL requires a configured `ConnectionStrings__DefaultConnection`. Jenkins integration is implemented but requires Jenkins credentials and webhook secret. Gitleaks and Trivy report parsing exists; SonarQube parsing exists but is not wired into the Jenkinsfile. Git diff sensitive-configuration analysis is not implemented. Python Azure OpenAI calls are real when configured and mocked in unit tests. No real Azure OpenAI call has been verified.

## Local development

Copy `.env.example` to `.env` and replace placeholders. `docker compose up --build` starts SQL Server, API and AI service. The existing database does not currently have automatic migrations or initialization in Compose; apply the SQL scripts or provision the schema separately before using API data endpoints. Configure Azure OpenAI endpoint, key and deployment for real AI responses. For direct local frontend use: `cd frontend; npm ci; npm run dev`. Backend: `dotnet run --project backend/AzureGuard/AzureGuard`.

## Interview overview

Explain the persisted release and scan model, normalization by `ScannerReportParser`, and policy decision path through `ReleaseService` and `RiskPolicyEngine`. The score is an explicitly project-specific rule policy, not a recognized security standard. Azure OpenAI produces remediation guidance only. Jenkins upload uses HMAC validation for raw scanner reports.
