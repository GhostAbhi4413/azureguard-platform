# AzureGuard Project Status

## Project

**AI-Powered DevSecOps Release Risk Platform**

The platform is intended to answer one important question:

> Is this release safe enough to deploy?

## Honest current progress

### Overall estimate: 30–35%

This is a strong foundation and an early working prototype. It is not yet a complete DevSecOps platform.

| Area | Current status | Estimate |
|---|---|---:|
| Layered backend structure | Created and connected | 70% |
| Azure SQL integration | EF Core configuration and schema alignment started | 45% |
| JWT authentication | Signup, login, password hashing | 55% |
| Project management | Project CRUD implemented | 70% |
| Repository analysis | Basic public GitHub file detection | 40% |
| Release management | Create and list releases | 35% |
| Risk engine | Basic rule-based score and decision | 45% |
| React frontend | Live API pages, no mock records | 45% |
| Swagger | Configured | 80% |
| Jenkins integration | Trigger/webhook structure only | 25% |
| Real scanner execution | Not working end-to-end yet | 0% |
| AI explanation | Not implemented | 0% |
| Deployment to ACR/AKS | Not implemented | 0% |
| Automated tests | Not implemented | 0% |
| Production hardening | Not implemented | 15% |

## Completed

### Backend

- ASP.NET Core Web API solution created.
- Projects separated into CoreModels, DataAccessLayer, BusinessLayer, ApplicationLayer, and API controllers.
- Generic `IRepository<T>` and repository implementation created.
- Azure SQL EF Core `AppDbContext` created.
- Existing Azure SQL schema mapped for core entities.
- JWT signup and login implemented.
- Password hashing implemented with PBKDF2.
- Project create, read, update, and soft-delete endpoints implemented.
- Release creation and release history endpoints implemented.
- Scan-result ingestion endpoint implemented.
- Rule-based risk scoring implemented.
- Approved, Manual Review, and Blocked decisions implemented.
- Release dashboard endpoint implemented.
- Repository analyzer added for public GitHub repositories.
- Jenkins trigger and webhook structure added, but it requires a Jenkins server.
- Swagger configured.
- CORS configured for local React development.

### Frontend

- React/Vite frontend created.
- JWT session handling implemented.
- Signup and login pages created.
- Project list page created.
- Project creation form created.
- Project edit and delete actions created.
- Automatic repository analysis message added.
- Release history page created.
- Release creation form created.
- Release decision page created.
- Scan result table created.
- Risk score and policy decision display created.
- Frontend uses live API calls and does not use mock project or release data.

### Verification

- Backend solution builds successfully.
- Frontend production build succeeds.
- Duplicate `ApplicationLayers` solution entry was removed.
- Correct `ApplicationLayer` project was added to the solution.
- CORS redirect issue was fixed for local development.
- Azure SQL connectivity progressed from unavailable database to a real schema-column error, proving the API reached the database.

## Important current limitations

- Jenkins is not available on the company laptop.
- The Jenkins integration is currently an adapter, not a verified live pipeline.
- The application currently accepts manually submitted scan totals through the API.
- Scanner reports are not yet parsed into detailed findings.
- Policy rules are partly represented in the database but the running engine still contains hardcoded rules.
- The database contains more tables than the current backend fully uses.
- Repository analysis currently supports public GitHub tree inspection and is not a complete private-repository analyzer.
- The webhook endpoint needs authentication with a secret before production use.
- The default JWT and Azure SQL values must remain placeholders in source code.

## Pending work, in the correct order

### Phase 1 — Complete the release decision core

1. Finish database mappings for PipelineRuns, ScanFindings, Policies, PolicyRules, AuditLogs, DeploymentTargets, Deployments, AiExplanations, and AiUsageLogs.
2. Add proper database migration/upgrade scripts.
3. Store individual scan findings, not only severity totals.
4. Make the policy engine load active rules from Azure SQL.
5. Add validation for scan types, severities, counts, project ownership, and release state transitions.
6. Add audit logging for project creation, release creation, scan ingestion, and policy decisions.
7. Add role-based authorization for Developer, Reviewer, and Admin.

### Phase 2 — Add the real pipeline provider

1. Move the application behind a provider abstraction.
2. Configure Jenkins on the personal laptop or another approved environment.
3. Create the Jenkins job linked to the repository.
4. Verify checkout, build, and test stages.
5. Add SonarQube, Trivy, Gitleaks, and Checkov execution.
6. Parse each report into normalized `ScanFindings` and `ScanResults` records.
7. Secure the Jenkins webhook.
8. Connect release creation to pipeline triggering.
9. Verify the full flow using a real repository and real scan output.

### Phase 3 — Make the risk decision credible

1. Define and document the scoring formula.
2. Include test results, previous failures, critical/high findings, secrets, and IaC failures as features.
3. Persist the exact feature values used for every decision.
4. Store the policy rules that caused the decision.
5. Add manual-review approval and rejection actions.
6. Prevent deployment unless the release is Approved.

### Phase 4 — Add AI explanation

1. Integrate Gemini through a backend service.
2. Send only the release evidence needed for explanation.
3. Store the explanation and recommended actions.
4. Log provider status and token usage.
5. Make it clear that Gemini explains a decision; it does not override policy rules.

### Phase 5 — Add deployment capability

1. Add deployment-target CRUD.
2. Add ACR image publishing.
3. Add Helm-based AKS deployment.
4. Add health checks.
5. Add deployment status and failure handling.
6. Add rollback to the previous successful release.

### Phase 6 — Professional quality

1. Add backend unit and integration tests.
2. Add frontend component and API tests.
3. Add pagination and filtering.
4. Add structured logging and correlation IDs.
5. Add retry handling for Azure SQL and external services.
6. Add rate limiting and secure headers.
7. Add secret management through Azure Key Vault.
8. Add monitoring and useful operational error messages.
9. Add deployment documentation and architecture diagrams.

## What would make this project stand out

The project becomes genuinely impressive when it demonstrates this live sequence:

```text
Create project
  -> Repository automatically analyzed
  -> Create release
  -> Real pipeline runs
  -> Real security reports are collected
  -> Findings are normalized and stored
  -> Risk score is calculated from evidence
  -> Database-driven policy decides Approved/Review/Blocked
  -> Gemini explains the decision
  -> Dashboard shows the evidence
  -> Only approved releases can deploy
```

That is the “boom” moment: not the number of screens, but a release being blocked for a real secret or critical vulnerability with visible evidence and an auditable reason.

## Current implementation note

Phase 1 release-core changes, normalized findings, feature persistence, audit events, SQL upgrade/seed script, signed Jenkins webhook validation, repository CI workflow, and frontend pipeline controls are implemented. Backend and frontend release builds pass with zero warnings/errors.

## Final assessment

The project is not trash or empty. The architecture, initial API, database connection, and frontend foundation are real work. But CRUD plus a dashboard is not yet DevSecOps.

The hardest and most valuable part is still ahead: real pipeline execution, real scanner output, correct policy evaluation, and trustworthy release decisions.

If Phase 1 and Phase 2 are completed properly, the project will move from an early prototype to a credible interview/demo project. If the complete flow through AI explanation and controlled deployment is finished with tests and security, it can become a genuinely strong portfolio project.
