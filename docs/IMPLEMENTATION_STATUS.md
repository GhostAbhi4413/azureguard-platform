# Implementation status

| Component | Status | Notes |
|---|---|---|
| React + TypeScript UI | Implemented | Existing Vite client retained; pre-existing local edits preserved. |
| Angular + TypeScript UI | Implemented, build unverified | Separate dashboard uses findings, deterministic decision, and AI remediation endpoints with loading/error display. |
| ASP.NET Core API | Implemented | Auth, projects, releases, scans, Jenkins and added findings/risk/AI routes. |
| SQL Server/Azure SQL | Implemented with setup gap | EF Core context and SQL scripts exist; no automatic migration/bootstrap. |
| Risk engine | Implemented | Deterministic local weighted policy, critical hard block, duplicate normalized finding collapse, failed scanner review. |
| Scanner reports | Partial | Gitleaks, Trivy, Checkov, SonarQube, JUnit parsers; Jenkins workflow runs Gitleaks/Trivy. |
| AI remediation | Implemented, external call unverified | FastAPI + Azure OpenAI SDK; tests use mock. Requires endpoint, key, deployment. |
| Docker | Partial | Compose and Dockerfiles provided; database schema bootstrap is manual. Docker validation depends on installed Docker. |
| GitHub Actions | Implemented | Build, frontend build, Python tests, Gitleaks and Trivy. Branch protection must be configured separately. |
| Angular migration | Planned | Current React app remains; no Angular project was created. |
| SonarQube CI and Git diff analysis | Planned | Parser exists, CI execution and sensitive diff policy do not. |

Use `.env.example` for placeholders only. No production readiness or live Azure integration is claimed.
