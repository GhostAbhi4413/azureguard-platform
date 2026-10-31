# Implementation status

| Component | Status | Notes |
|---|---|---|
| React + TypeScript UI | Implemented | Existing Vite client retained; pre-existing local edits preserved. |
| Angular + TypeScript UI | Implemented, build unverified | Separate dashboard uses findings, deterministic decision, and AI remediation endpoints with loading/error display. |
| ASP.NET Core API | Implemented | Auth, projects, releases, scans, Jenkins and findings/risk/AI routes. |
| SQL Server/Azure SQL | Implemented with setup gap | EF Core context and SQL scripts exist; no automatic migration/bootstrap. |
| Risk engine | Implemented | Deterministic local weighted policy, critical hard block, duplicate normalized finding collapse, failed scanner review. |
| Scanner reports | Partial | Gitleaks, Trivy, Checkov, SonarQube, JUnit parsers; Jenkins workflow runs Gitleaks/Trivy. |
| AI remediation | Implemented, external call unverified | ASP.NET Core calls Azure OpenAI directly with C# `HttpClient`; mocked tests cover redaction, response mapping and provider errors. Requires endpoint, key, deployment. |
| Docker | Partial | Compose and Dockerfiles for API, Angular and SQL Server; database schema bootstrap is manual. |
| GitHub Actions | Implemented | Build and tests for .NET; builds Angular and retained React; Gitleaks and Trivy scans. Jenkins submits both scanner reports and fails on BLOCKED or REVIEW_REQUIRED. Branch protection must be configured separately. |
| Angular + TypeScript UI | Implemented, build unverified | Login, findings pagination, decision display and AI remediation call connected to API. React remains available during transition. |
| SonarQube CI and Git diff analysis | Partial | SonarQube parser accepts normalized reports; Jenkins does not run SonarQube, and sensitive Git diff policy is not implemented. |

There is no Python/FastAPI component by design. Use `.env.example` for placeholders only. No production readiness or live Azure integration is claimed.
