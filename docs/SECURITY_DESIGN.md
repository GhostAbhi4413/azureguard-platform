# Security design

- API uses JWT bearer authentication and role checks on reviewer decisions. Supply a strong `Jwt__Key` through environment/secret configuration.
- Database credentials, webhook secret, and Azure OpenAI key belong in environment or secret stores; never commit real values.
- Raw scanner reports use HMAC SHA-256 validation on the existing report endpoint. Jenkins webhook uses a shared secret.
- AI request schema accepts sanitized finding metadata only and excludes source contents and secrets. The AI response is advisory and is not used in risk evaluation.
- Critical findings are hard blocked. Other severity weights and thresholds are local policy choices, not an external standard. Scanner failures require manual review.
- Findings API caps page size at 200 and uses EF Core `AsNoTracking` for reads.
- CI runs Gitleaks and Trivy filesystem checks. Configure workflow status as required and enable branch protection separately.

Remaining review items include deployment-grade secret rotation, authentication/authorization threat review, SQL schema bootstrap/migrations, rate limiting, and verification of Azure OpenAI and Jenkins credentials in a controlled environment.
