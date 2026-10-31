# Architecture

AzureGuard records projects and releases, ingests normalized scanner reports, evaluates a deterministic risk policy, and exposes findings and decisions to clients. The existing React + TypeScript + Vite client remains in `frontend/`; a separate Angular + TypeScript client is in `frontend-angular/` so the existing app is preserved.

## Request flow

Angular calls the authenticated ASP.NET Core API. Controllers validate requests and use EF Core (`AppDbContext`) against SQL Server/Azure SQL. Release scan ingestion stores `ScanResult` and `ScanFinding` rows; `RiskPolicyEngine` applies deterministic local weights (critical 25, high 6, medium 2, low 0.25; capped at 100) and critical hard block. Failed scanners return `REVIEW_REQUIRED`. Azure OpenAI is called directly from the .NET `AzureOpenAiRemediationService`; it cannot affect release decisions.

## Endpoints

Existing endpoints include `/api/auth/signup`, `/api/auth/login`, `/api/projects`, `/api/projects/{projectId}/releases`, nested release `scans`, `reports`, `dashboard`, `pipeline`, `approve`, `reject`, and `deploy`. New authenticated endpoints are `GET /api/releases/{releaseId}/findings?page=1&pageSize=50`, `POST /api/releases/{releaseId}/risk-evaluation`, and `POST /api/ai/remediation`. The .NET AI service sends only scanner, finding ID, severity, file location, description and commit reference directly to Azure OpenAI. It redacts common credential patterns and accepts no source-code field.

## Components

The database layer uses EF Core with SQL Server and existing SQL scripts; Azure SQL requires a configured `ConnectionStrings__DefaultConnection`. Jenkins integration is implemented but requires Jenkins credentials and webhook secret. Gitleaks, Trivy, Checkov and SonarQube report parsing exists; Jenkins executes Gitleaks and Trivy. Git diff sensitive-configuration analysis is not implemented. Azure OpenAI uses the documented chat completions REST endpoint from C# `HttpClient`; mocked unit tests cover successful structured output, redaction and provider errors. No real Azure OpenAI call has been verified.

## Local development

Copy `.env.example` to `.env` and replace placeholders. `docker compose up --build` starts SQL Server, API and Angular UI. The existing database does not currently have automatic migrations or initialization in Compose; apply the SQL scripts or provision the schema separately before using API data endpoints. Configure `AzureOpenAI__Endpoint`, `AzureOpenAI__ApiKey`, and `AzureOpenAI__Deployment` for real AI responses. For direct local frontend use: `cd frontend-angular; npm install; npm start`. Backend: `dotnet run --project backend/AzureGuard/AzureGuard`.

## Interview overview

Explain the persisted release and scan model, normalization by `ScannerReportParser`, and policy decision path through `ReleaseService` and `RiskPolicyEngine`. The score is an explicitly project-specific rule policy, not a recognized security standard. Azure OpenAI produces remediation guidance only. Jenkins upload uses HMAC validation for raw scanner reports.
