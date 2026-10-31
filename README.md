# AzureGuard

AzureGuard is a DevSecOps release-risk platform built around the existing ASP.NET Core API, EF Core SQL Server models, repository layer, scanner report parsers, and deterministic policy engine. The repository contains two frontends: the Angular + TypeScript dashboard in `frontend-angular/` is the active dashboard, while the existing React + TypeScript app in `frontend/` is retained during the transition.

## Request flow

Angular signs in through ASP.NET Core, then requests paginated findings and a deterministic release decision. For remediation guidance, Angular posts sanitized finding metadata to `POST /api/ai/remediation`. The .NET API validates and redacts the metadata, then forwards it to the internal Python FastAPI service at `POST /api/remediation`. That service calls the configured Azure OpenAI deployment and returns a typed explanation, impact, remediation, and prevention list. AI guidance is advisory; it never changes the risk decision.

The scanner parser accepts Gitleaks, Trivy, Checkov, SonarQube and JUnit reports. Gitleaks and Trivy run in the existing Jenkins pipeline. Jenkins submits the reports to the API; the last report finalizes policy evaluation and the pipeline fails for `BLOCKED` or `REVIEW_REQUIRED`.

## Run locally

Copy `.env.example` to `.env` and provide local SQL settings plus valid Azure OpenAI endpoint, API key and deployment values. Never commit real credentials. The API uses `AI__BaseUrl` (default `http://localhost:8000`) for the Python service; Compose sets this to `http://ai:8000` on its internal network.

Apply the SQL scripts in `backend/database` to SQL Server or Azure SQL; Compose does not run migrations. Start the API with `dotnet run --project backend/AzureGuard/AzureGuard`, the AI service with `python -m uvicorn app.main:app --app-dir ai-service --port 8000`, and Angular with `npm ci && npm start` from `frontend-angular`. Angular uses `http://localhost:5006/api` by default. The React app remains available with `npm ci && npm run dev` from `frontend`.

With configured `.env` values, `docker compose up --build` starts SQL Server, API, Python AI service, and Angular. Ports are 1433, 5006 and 4200; the AI service is internal to the Compose network. The database schema still needs to be applied separately.

## API routes

- `POST /api/auth/signup` and `/api/auth/login`
- Existing `/api/projects` and `/api/projects/{projectId}/releases` endpoints, including nested scan ingestion and dashboard routes
- `GET /api/releases/{releaseId}/findings?page=1&pageSize=50`
- `POST /api/releases/{releaseId}/risk-evaluation`
- `POST /api/ai/remediation` → internal Python `POST /api/remediation`

Risk decisions are `APPROVED`, `REVIEW_REQUIRED`, and `BLOCKED`. Critical findings are hard blocked; scanner failures require review. Severity weights are project policy values, not a published security standard.

## Checks

```powershell
dotnet restore backend/AzureGuard/AzureGuard.sln --configfile backend/NuGet.Config -m:1
dotnet build backend/AzureGuard/AzureGuard.sln -c Release --no-restore -m:1
dotnet test backend/AzureGuard/AzureGuard.sln -c Release --no-build -m:1
npm ci --prefix frontend-angular
npm run build --prefix frontend-angular
npm ci --prefix frontend
npm run build --prefix frontend
python -m pip install -r ai-service/requirements.txt
python -m pytest ai-service/tests -q
docker compose config
```

GitHub Actions runs .NET builds/tests, both frontend builds, Python tests, Gitleaks and Trivy. Jenkins uploads scanner reports and enforces the policy decision. Configure required status checks and branch protection separately. SonarQube report parsing exists, but CI does not run SonarQube. Sensitive Git-diff analysis is not implemented. Live Azure OpenAI, SQL and Jenkins integrations require credentials and environment verification; this repository makes no production-readiness claim.

See [architecture](docs/ARCHITECTURE.md), [implementation status](docs/IMPLEMENTATION_STATUS.md), and [security design](docs/SECURITY_DESIGN.md).
