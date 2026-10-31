# AzureGuard Project Status

## Current implementation

AzureGuard is an ASP.NET Core 8 API with EF Core SQL Server models, repositories, release/scanner ingestion, a deterministic risk engine, a React application retained during transition, and a separate Angular + TypeScript dashboard. Azure OpenAI remediation now runs directly in the .NET API through a typed service using `HttpClient`; the repository has no Python AI service.

| Area | Status | Evidence / limitation |
|---|---|---|
| Backend API and EF Core | Implemented | Existing layered solution, SQL Server context, auth, projects, releases and scan routes; SQL schema still must be provisioned manually. |
| Risk policy | Implemented | Decisions are `APPROVED`, `REVIEW_REQUIRED`, `BLOCKED`; critical findings hard block, scanner failure requires review. Weights are local policy choices. |
| Scanner ingestion | Partial | Gitleaks, Trivy, Checkov, SonarQube and JUnit parsers normalize reports; Jenkins executes Gitleaks and Trivy. SonarQube and Git diff scans are not run in CI. |
| Azure OpenAI | Implemented, live call unverified | C# service sends sanitized finding metadata, redacts credential patterns, uses timeout/retry and returns structured guidance. Requires endpoint, deployment and key. Mock HTTP tests cover output, redaction and provider errors. |
| Angular app | Implemented | Login, findings, release decision and AI explanation views connect to the API. |
| React app | Retained and builds | Existing functionality remains while Angular is brought forward. |
| CI/CD | Partial | GitHub Actions builds/tests .NET and Angular, builds React, runs Gitleaks/Trivy. Jenkins submits reports and fails on `BLOCKED` and `REVIEW_REQUIRED`. Configure branch protections separately. |
| Docker | Configuration present | Compose starts SQL Server, API and Angular; SQL schema setup is manual. Compose config validates; images were not built here. |
| Automated checks | Passed locally | .NET solution build, 7 .NET tests, Angular production build, React production build, Angular npm audit, Compose config validation. No live Azure SQL/OpenAI/Jenkins execution. |

## Known gaps

- Azure SQL schema initialization/migrations are not automated.
- No real Azure OpenAI call has been verified; values must be supplied through environment/secret configuration.
- SonarQube is parsed by the backend but not executed by Jenkins or GitHub Actions. Git diff sensitive-configuration detection is not implemented.
- No Angular component test suite is configured; the Angular production build passes.
- The policy engine uses project-defined severity weights; these are not an external standard.
- Authentication, authorization, rate limiting, secret rotation and deployment hardening need a separate review before production use.

See `README.md`, `docs/ARCHITECTURE.md`, and `docs/SECURITY_DESIGN.md` for local setup and request flow.
