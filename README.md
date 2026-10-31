# AzureGuard

AzureGuard is a DevSecOps release risk platform built around the existing ASP.NET Core API, EF Core SQL Server models, repository layer, scanner report parser and deterministic risk policy. The repository includes the existing React application and a separate Angular + TypeScript dashboard; Angular is the target UI and React remains available during transition.

## Architecture

The Angular app signs in through the API, then loads paginated findings and the release risk decision. It can request advisory remediation from the same .NET API. ASP.NET Core sanitizes scanner metadata and calls Azure OpenAI directly with `HttpClient`; there is no Python AI service. AI output never changes the deterministic release decision.

The scanner parser accepts Gitleaks, Trivy, Checkov, SonarQube and JUnit formats. The risk engine returns `APPROVED`, `REVIEW_REQUIRED` or `BLOCKED`. Critical findings are hard blocked; scanner failures require review. Other severity weights are local policy values, not an external security standard.

## Run locally

1. Configure `ConnectionStrings__DefaultConnection`, `Jwt__Key` and optionally the `AzureOpenAI__Endpoint`, `AzureOpenAI__ApiKey`, `AzureOpenAI__Deployment`, `AzureOpenAI__ApiVersion` and `AzureOpenAI__TimeoutSeconds` environment values. Do not commit credentials. `.env.example` contains placeholders.
2. Apply the existing SQL scripts in `backend/database` to a local SQL Server/Azure SQL database. Automatic schema migration is not configured.
3. Start the API with `dotnet run --project backend/AzureGuard/AzureGuard`.
4. Start Angular with `npm ci && npm start` from `frontend-angular`; open `http://localhost:4200`. Use a registered account. React remains runnable from `frontend` with `npm ci && npm run dev`.
5. For local containers, use `docker compose up --build`; the Angular app is on port 4200 and the API on port 5006. Database schema setup remains manual.

## API endpoints

- `POST /api/auth/login` and `POST /api/auth/signup`
- Existing `/api/projects` and `/api/projects/{projectId}/releases` endpoints, including nested scan ingestion and dashboards
- `GET /api/releases/{releaseId}/findings?page=1&pageSize=50`
- `POST /api/releases/{releaseId}/risk-evaluation`
- `POST /api/ai/remediation` (authenticated; calls Azure OpenAI directly)

## Verification

```powershell
dotnet restore backend/AzureGuard/AzureGuard.sln --configfile backend/NuGet.Config -m:1
dotnet build backend/AzureGuard/AzureGuard.sln --configuration Release --no-restore -m:1
dotnet test backend/AzureGuard/AzureGuard.sln --configuration Release --no-build -m:1
npm install --prefix frontend-angular
npm run build --prefix frontend-angular
npm ci --prefix frontend
npm run build --prefix frontend
docker compose config
```

GitHub Actions builds and tests the .NET solution and Angular app, builds the retained React app, and runs Gitleaks and Trivy filesystem scans. Jenkins handles release report ingestion; the final scanner upload triggers policy evaluation. GitHub required checks and branch protection are configured separately. Live Azure OpenAI, SQL and Jenkins credentials are environment-specific and must be verified in the target environment.

See [architecture](docs/ARCHITECTURE.md), [implementation status](docs/IMPLEMENTATION_STATUS.md), and [security design](docs/SECURITY_DESIGN.md).
