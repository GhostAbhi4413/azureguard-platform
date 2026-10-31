# Implementation status

| Component | Status | Notes |
|---|---|---|
| React + TypeScript UI | Retained | Existing Vite client remains available during Angular transition. |
| Angular + TypeScript UI | Implemented | Dashboard login and views use .NET findings, risk-evaluation, and AI-remediation endpoints. |
| ASP.NET Core API | Implemented | Auth, projects, releases, scans, Jenkins and findings/risk/AI routes. |
| SQL Server/Azure SQL | Implemented with setup gap | EF Core context and SQL scripts exist; no automatic migration/bootstrap. |
| Risk engine | Implemented | Deterministic local weighted policy, critical hard block, duplicate normalized finding collapse, failed scanner review. |
| Scanner reports | Partial | Gitleaks, Trivy, Checkov, SonarQube, JUnit parsers; Jenkins workflow runs Gitleaks/Trivy. |
| AI remediation | Implemented, external call unverified | .NET forwards redacted DTOs to Python FastAPI; Python uses Azure OpenAI. Python tests mock the AI client; .NET tests mock the HTTP boundary. Requires endpoint, key, deployment. |
| Docker | Partial | Compose and Dockerfiles for API, Angular, Python AI and SQL Server; database schema bootstrap is manual. Requires SQL/JWT/Azure OpenAI values in `.env`. |
| GitHub Actions | Implemented | Builds/tests .NET, builds Angular and retained React, runs mocked Python AI tests, Gitleaks and Trivy. Jenkins submits reports and fails on `BLOCKED` or `REVIEW_REQUIRED`. Branch protection must be configured separately. |
| SonarQube and Git diff | Incomplete | SonarQube parser exists, but the CI pipelines do not execute it. Sensitive Git-diff detection is not implemented. |

Use `.env.example` for placeholders only. No live Azure OpenAI/SQL integration or production readiness is claimed.
