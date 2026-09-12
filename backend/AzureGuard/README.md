# AzureGuard backend

## Run locally

1. Run `backend/database/002_add_auth_password_hash.sql`, then `backend/database/003_phase1_release_core.sql` against the Azure SQL database.
2. Set `ConnectionStrings:DefaultConnection` and `Jwt:Key` using user secrets or environment variables. Do not commit real credentials.
3. Start the API from `backend/AzureGuard/AzureGuard`.

## Implemented API

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET|POST|PUT|DELETE /api/projects`
- `GET|POST /api/projects/{projectId}/releases`
- `POST /api/projects/{projectId}/releases/{releaseId}/scans`
- `GET /api/projects/{projectId}/releases/{releaseId}/dashboard`

All project and release endpoints require a JWT bearer token. Scan ingestion evaluates the stored scan totals using the rule-based policy engine and persists the risk score, decision, and release status.

## CI/CD

- `.github/workflows/ci.yml` restores/builds the .NET solution and creates the Vite production bundle on pushes and pull requests.
- `Jenkinsfile` provides checkout/build/test/security-scan stages for the Jenkins adapter.
- Scan ingestion accepts optional normalized `findings` entries in addition to severity totals; Jenkins webhooks require `X-AzureGuard-Webhook-Secret`.
