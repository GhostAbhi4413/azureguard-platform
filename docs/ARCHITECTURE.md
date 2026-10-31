# Architecture

AzureGuard retains its Angular and React frontends, ASP.NET Core API, EF Core SQL persistence, Python FastAPI AI integration, scanner reports, Jenkins and deterministic policy engine. React remains available while Angular is the primary UI.

## Request flow

Angular signs users in, lists/creates projects and releases, displays findings and the deterministic policy result, and shows the latest stored change-impact analysis for a selected release. All client requests use the existing ASP.NET Core API and bearer authentication.

For remediation, `.NET POST /api/ai/remediation` sanitizes finding metadata and forwards it to Python `POST /api/remediation`. For pull-request impact analysis, GitHub Actions can submit a signed base-to-head diff to the existing raw report route. .NET normalizes scanner findings, selects security-relevant files/lines, redacts credentials and instruction-like prompt text, applies a 2 MB intake and 12 KB AI-context limit, then calls Python `POST /api/change-impact`. Python sanitizes again, treats repository content as untrusted data, calls Azure OpenAI, and validates the structured JSON. The .NET layer stores the response, commit reference, model/deployment metadata, and explicit `SKIPPED` or `UNAVAILABLE` status in `AIChangeImpactAnalyses`; it does not store the raw PR patch. Angular reads it from the release's `change-impact` GET route.

AI risk and manual-review recommendations are advisory. The existing `RiskPolicyEngine` remains the sole release policy authority; AI output cannot approve or block a release.

## Endpoints

- Auth and project/release lifecycle: `POST /api/auth/signup`, `POST /api/auth/login`, `/api/projects`, `/api/projects/{projectId}/releases`.
- Findings/policy: `GET /api/releases/{releaseId}/findings`, `POST /api/releases/{releaseId}/risk-evaluation`.
- Existing remediation: `.NET POST /api/ai/remediation` → Python `POST /api/remediation`.
- PR report ingest: signed `POST /api/projects/{projectId}/releases/{releaseId}/reports/raw?scanType=GIT_DIFF&toolName=GIT_DIFF&status=PASSED&finalize=false&commitReference={sha}`.
- Change impact: internal Python `POST /api/change-impact`; authenticated Angular read `GET /api/projects/{projectId}/releases/{releaseId}/change-impact`.
- Existing scanner, dashboard, Jenkins pipeline, review and deployment-gate routes remain in the nested release controller.

GitHub Actions collects the pull-request diff only when API URL, project ID, release ID and webhook-secret repository secrets are configured. The release must already exist. Jenkins continues its scanner report flow; Gitleaks and Trivy feed the deterministic risk engine. SonarQube issue JSON has a parser and fixture test, and CI scanning is optional when Sonar credentials are configured; the workflow does not attach Sonar results automatically to a release.

## Azure OpenAI configuration

The underlying Azure model ID is `gpt-4.1-mini` (model version `2025-04-14`). `AZURE_OPENAI_DEPLOYMENT` is the Azure resource's deployment name, defaults to `gpt-4.1-mini`, and is sent in the SDK's `model` parameter; the deployment must actually exist in that resource. The integration uses API version `v1` at `/openai/v1/chat/completions` through Python OpenAI SDK `AsyncOpenAI` and API-key authentication. Configure `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT`, and `AZURE_OPENAI_API_VERSION` through environment or a secure secret store. Endpoint/key are blank in `.env.example`; missing values produce explicit HTTP 503 on AI calls. Tests inject mocks. No authenticated Azure OpenAI request has been verified.

## Persistence and local setup

EF Core stores projects, releases, findings, decisions and change-impact result rows in SQL Server/Azure SQL. `backend/database/003_phase1_release_core.sql` adds the analysis table idempotently. Apply schema setup explicitly with `tools/initialize-local-sql.ps1`; neither application startup nor Docker Compose runs schema changes automatically. See README for repeatable local setup and connection requirements.

## Verification boundaries

Git diff detection is heuristic and source context is intentionally bounded. Model output and persisted findings do not alter deterministic release authority. Live Azure OpenAI, SQL persistence, GitHub-secret delivery, Jenkins, SonarQube server execution, browser end-to-end flows and Docker container startup require external services and were not verified by local mocked builds/tests.
