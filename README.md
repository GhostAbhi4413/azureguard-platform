# AzureGuard

AzureGuard is a release risk tracking project with an ASP.NET Core API, SQL Server data model, an existing React client, and a separate Angular/TypeScript dashboard. It ingests scanner findings and applies deterministic release policy rules.

See [architecture](docs/ARCHITECTURE.md), [implementation status](docs/IMPLEMENTATION_STATUS.md), and [security design](docs/SECURITY_DESIGN.md) for scope and limitations.

## Run locally

Copy `.env.example` to `.env`, replace local placeholders, then run `docker compose up --build`. The SQL schema must be applied separately using the scripts in `backend/database`; Compose does not run migrations. For direct development, use `npm ci && npm run dev` in `frontend`, `dotnet run --project backend/AzureGuard/AzureGuard` for the API, and `python -m uvicorn app.main:app --app-dir ai-service --reload --port 8000` for AI.

Configure `ConnectionStrings__DefaultConnection`, `Jwt__Key`, and (for live AI) `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, and `AZURE_OPENAI_DEPLOYMENT` through environment variables or secret storage. AI integration has not been tested with live credentials.

## Verification commands

```powershell
dotnet restore backend/AzureGuard/AzureGuard.sln --configfile backend/NuGet.Config
dotnet build backend/AzureGuard/AzureGuard.sln --configuration Release --no-restore
npm ci --prefix frontend
npm run build --prefix frontend
python -m pip install -r ai-service/requirements.txt
python -m compileall ai-service/app
python -m pytest ai-service/tests
docker compose config
```

GitHub Actions runs API build, React and Angular builds, Python tests, Gitleaks and Trivy on pull requests and pushes to `main`. To build Angular locally run `npm install && npm run build` in `frontend-angular`. Required status checks and branch protection must be configured in GitHub separately. See implementation status for components that remain planned or unverified.
