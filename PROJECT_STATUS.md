# AzureGuard Project Status

## Current implementation

AzureGuard uses the existing ASP.NET Core API, EF Core SQL Server models, repositories, scan parsers and deterministic policy engine. The active dashboard is Angular + TypeScript in `frontend-angular/`; the existing React/Vite app in `frontend/` remains available during the transition.

AI remediation is a two-hop flow: Angular calls the authenticated .NET `POST /api/ai/remediation`; the .NET typed client forwards sanitized finding metadata to internal FastAPI `POST /api/remediation`; Python calls the configured Azure OpenAI deployment. Mocked Python tests and .NET HTTP-boundary tests cover the contract. No live Azure OpenAI request has been verified.

| Area | Status | Evidence / remaining limitation |
|---|---|---|
| ASP.NET Core and EF Core | Implemented | Existing layered API, SQL Server context, auth, project/release and scanner routes; SQL schema setup remains manual. |
| Risk policy | Implemented | Returns `APPROVED`, `REVIEW_REQUIRED` or `BLOCKED`; critical findings hard block and scanner failures require review. Weights are project-defined. |
| Scanner ingestion | Partial | Parsers exist for Gitleaks, Trivy, Checkov, SonarQube and JUnit. Jenkins executes Gitleaks and Trivy and uploads reports. |
| Angular dashboard | Implemented | Login, findings, risk decision and remediation are wired to the .NET API. |
| React dashboard | Retained | Existing Vite client still builds and remains available. |
| Python AI service | Implemented, live call unverified | FastAPI validates finding metadata and calls Azure OpenAI with configured timeout/retries; tests use a mocked AI client. |
| .NET AI bridge | Implemented | Validates/redacts the request, calls configured Python base URL, maps structured response, and handles timeouts/service errors. HTTP boundary is mocked in unit tests. |
| GitHub Actions and Jenkins | Implemented with gaps | Actions builds/tests .NET, both frontends and Python; Gitleaks and Trivy run in Actions. Jenkins uploads reports and fails on `BLOCKED`/`REVIEW_REQUIRED`. Branch protection is external configuration. |
| Docker Compose | Configured | SQL Server, API, Python AI service and Angular UI; configuration validation requires `.env` values. Schema bootstrap is manual. |
| SonarQube and Git-diff analysis | Incomplete | SonarQube report parser exists, but CI does not run the scanner. Sensitive Git-diff detection is not implemented. |

## Environment and verification limits

Set SQL connection/password and a strong JWT key in `.env`. Live AI requires a valid Azure OpenAI endpoint, API key and deployment. Local automated tests do not call Azure. Compose does not initialize the SQL schema. No production-readiness claim is made.
