# AzureGuard

AzureGuard is a DevSecOps release-risk project built on the existing ASP.NET Core API, EF Core SQL Server models, repository layer, scanner report parsers and deterministic risk policy. The active dashboard is Angular + TypeScript in `frontend-angular/`. The existing React/Vite app in `frontend/` remains available during the transition and provides the current sign-up screen.

## Visual walkthrough

The first visual illustrates the Angular sign-in, release review, finding list and remediation panel. Its release/finding values are illustrative UI content, not a captured live session or a claim that Azure OpenAI has returned that text.

![AzureGuard Angular UI flow illustration](docs/assets/azureguard-ui-flow.svg)

The system diagram below follows the implemented request boundaries. It also calls out features that remain incomplete or unverified.

![AzureGuard system and release flow](docs/assets/azureguard-system-flow.svg)

## What happens in the application

1. Angular signs in through `POST /api/auth/login`. On success, it stores the JWT in session storage and sends it as a Bearer token on protected API requests.
2. The user enters a release ID and clicks **Load release**. Angular calls `GET /api/releases/{releaseId}/findings?page=1&pageSize=50` and `POST /api/releases/{releaseId}/risk-evaluation`.
3. ASP.NET Core reads scanner results and normalized findings from EF Core/SQL Server. `RiskPolicyEngine` returns `APPROVED`, `REVIEW_REQUIRED`, or `BLOCKED`; AI has no role in that decision.
4. Clicking **Explain remediation** sends finding metadata to `POST /api/ai/remediation`. The .NET service validates and redacts credentials and source-like text, then forwards the metadata to Python `POST /api/remediation` using the configured `AI__BaseUrl`.
5. FastAPI validates the matching camel-case JSON contract. The Python service redacts the content again, then calls the configured Azure OpenAI deployment. It returns an explanation, potential impact, suggested remediation, and prevention measures. The Angular panel displays that response as advisory guidance.
6. In the scanner path, Jenkins runs Gitleaks and Trivy, signs and uploads their reports, and the .NET parser stores normalized findings. The last report finalizes policy evaluation. Jenkins fails the release gate for `BLOCKED` and `REVIEW_REQUIRED`.

The Angular page currently asks for a release ID directly; it does not provide project/release discovery. Create a project and release using the existing React application or the API before testing the Angular review view.

## Local setup

### Required configuration

Use .NET 8, Node.js 24, Python 3.12, and SQL Server or Azure SQL. Copy `.env.example` to `.env` and replace every `REPLACE_...`/`YOUR_...` value. Never commit the filled-in `.env` file or real credentials.

For Compose, `AZUREGUARD_SQL_CONNECTION` must point to the service host `db`, and its password must match `SQL_PASSWORD`, for example:

```text
AZUREGUARD_SQL_CONNECTION=Server=db,1433;Database=AzureGuard;User Id=sa;Password=<same value as SQL_PASSWORD>;Encrypt=False;
```

Set a long random `JWT_KEY`. For live remediation, set a real Azure OpenAI resource endpoint, API key, and deployment name in `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, and `AZURE_OPENAI_DEPLOYMENT`. `AZURE_OPENAI_API_VERSION` and `AZURE_OPENAI_TIMEOUT_SECONDS` are configurable too. Tests use a mock AI client and do not need Azure credentials.

Apply the existing scripts under `backend/database` to your SQL Server database before using data endpoints. Compose starts SQL Server but does not apply migrations or those SQL scripts automatically.

### Run all local services with Docker Compose

1. Copy `.env.example` to `.env` and fill in SQL, JWT, and Azure OpenAI settings.
2. Apply the SQL scripts to the Compose SQL Server (host port 1433) using your SQL client.
3. From the repository root, run:

   ```powershell
   docker compose up --build
   ```

4. Open Angular at `http://localhost:4200`. The API is published at `http://localhost:5006`; the Python AI service stays on the Compose network and is reached by the API at `http://ai:8000`.

### Run services directly for development

Start SQL Server/Azure SQL and apply the SQL scripts. When running services directly, PowerShell does not automatically read `.env`, so export the .NET settings in the API terminal (use your own local SQL credentials):

```powershell
$env:ConnectionStrings__DefaultConnection = 'Server=localhost,1433;Database=AzureGuard;User Id=sa;Password=<your-local-password>;Encrypt=False;'
$env:Jwt__Key = '<a-random-secret-of-at-least-32-characters>'
$env:AI__BaseUrl = 'http://localhost:8000'
dotnet run --project backend/AzureGuard/AzureGuard
```

In a second terminal from the repository root, export the Azure OpenAI values, then install and start the Python service:

```powershell
$env:AZURE_OPENAI_ENDPOINT = 'https://<your-resource>.openai.azure.com'
$env:AZURE_OPENAI_API_KEY = '<your-key>'
$env:AZURE_OPENAI_DEPLOYMENT = '<your-deployment-name>'
$env:AZURE_OPENAI_API_VERSION = '2024-10-21'
$env:AZURE_OPENAI_TIMEOUT_SECONDS = '25'
python -m pip install -r ai-service/requirements.txt
python -m uvicorn app.main:app --app-dir ai-service --host 127.0.0.1 --port 8000
```

In a third terminal, start Angular:

```powershell
cd frontend-angular
npm ci
npm start -- --open
```

The API must be reachable at `http://localhost:5006/api`. Angular currently has sign-in but no sign-up screen. To create an account, start the retained React app in another terminal (`cd frontend; npm ci; npm run dev`), use its sign-up option, then sign in through Angular.

## Try the real application flow

1. Register a user through React sign-up or `POST /api/auth/signup`. The account is stored by the .NET API in the configured SQL database.
2. Create a project and a release through the existing React app/API. Note the release ID.
3. Sign in to Angular at port 4200 with that account.
4. Enter the release ID and click **Load release**. The screen requests the stored findings and current deterministic policy result. If no reports have been ingested, the API will show the actual empty/current state; it does not substitute fabricated scan results.
5. To populate findings, trigger the configured Jenkins pipeline or upload a supported report through the existing release report endpoint. Gitleaks and Trivy parsing is wired into the Jenkins flow. The report must reach the API before the Angular findings list can display it.
6. Click **Explain remediation** on a finding. With valid Azure OpenAI configuration, the response travels Angular → .NET → Python → Azure OpenAI → Python → .NET → Angular. The AI output explains the finding but cannot approve or unblock the release.

If Angular reports `Http failure response ... 0 undefined`, the browser could not reach the API at `localhost:5006`; start the API and check its SQL configuration. If login returns unauthorized after the API is reachable, confirm the account was registered in the same database. If remediation returns service unavailable, check `AI__BaseUrl` from the API host and the Azure OpenAI settings available to the Python process.

## API routes used by the UI and pipeline

- `POST /api/auth/signup`, `POST /api/auth/login`
- Existing `/api/projects` and `/api/projects/{projectId}/releases` CRUD/release routes
- `GET /api/releases/{releaseId}/findings?page=1&pageSize=50`
- `POST /api/releases/{releaseId}/risk-evaluation`
- `POST /api/ai/remediation` → internal Python `POST /api/remediation`
- Existing nested release routes for scan ingestion, scanner report upload, dashboard, pipeline trigger, approve/reject, and deployment gate

## Build and test commands

```powershell
dotnet restore backend/AzureGuard/AzureGuard.sln --configfile backend/NuGet.Config -m:1
dotnet build backend/AzureGuard/AzureGuard.sln -c Release --no-restore -m:1
dotnet test backend/AzureGuard/AzureGuard.sln -c Release --no-build -m:1
npm ci --prefix frontend-angular
npm run build --prefix frontend-angular
npm ci --prefix frontend
npm run build --prefix frontend
python -m pip install -r ai-service/requirements.txt
python -m compileall ai-service/app
python -m pytest ai-service/tests -q
docker compose --env-file .env config
```

## Integration and scope status

GitHub Actions builds/tests .NET, builds Angular and retained React, runs the mocked Python AI tests, Gitleaks and Trivy. Jenkins submits scanner reports and enforces the deterministic policy decision. Configure GitHub required status checks and branch protection separately. SonarQube report parsing exists, but the CI workflows do not run SonarQube. Sensitive Git-diff analysis is not implemented.

Local mocked tests do not prove a live Azure OpenAI response. Azure OpenAI, Azure SQL, Jenkins credentials, scanner execution in your environment, and Docker image startup require their configured external services. No production-readiness claim is made.

More detail: [architecture](docs/ARCHITECTURE.md), [implementation status](docs/IMPLEMENTATION_STATUS.md), and [security design](docs/SECURITY_DESIGN.md).
