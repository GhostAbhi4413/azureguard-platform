using System.ComponentModel.DataAnnotations;
using System.Net.Http.Json;
using ApplicationLayer;
using BusinessLayer;
using CoreModels;
using DataAccessLayer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AzureGuard.Controllers;

[ApiController]
[Authorize]
[Route("api")]
public sealed class SecurityController(AppDbContext db, RiskPolicyEngine engine, IHttpClientFactory clients) : ControllerBase
{
    [HttpGet("releases/{releaseId:long}/findings")]
    public async Task<IActionResult> Findings(long releaseId, [FromQuery] int page = 1, [FromQuery] int pageSize = 50, CancellationToken cancellationToken = default)
    {
        if (page < 1 || pageSize is < 1 or > 200) return BadRequest("page must be positive and pageSize must be between 1 and 200.");
        if (!await db.Releases.AnyAsync(x => x.Id == releaseId, cancellationToken)) return NotFound();
        var query = db.ScanFindings.AsNoTracking().Where(x => x.ReleaseId == releaseId).OrderByDescending(x => x.CreatedAt);
        var total = await query.CountAsync(cancellationToken);
        var items = await query.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
        return Ok(new { page, pageSize, total, items });
    }

    [HttpPost("releases/{releaseId:long}/risk-evaluation")]
    public async Task<IActionResult> Evaluate(long releaseId, CancellationToken cancellationToken)
    {
        var release = await db.Releases.AsNoTracking().SingleOrDefaultAsync(x => x.Id == releaseId, cancellationToken);
        if (release is null) return NotFound();
        var scans = await db.ScanResults.AsNoTracking().Where(x => x.ReleaseId == releaseId).ToListAsync(cancellationToken);
        var rules = await db.PolicyRules.AsNoTracking().Where(x => x.IsActive && db.Policies.Any(p => p.Id == x.PolicyId && p.ProjectId == release.ProjectId && p.IsActive)).ToListAsync(cancellationToken);
        var result = engine.Evaluate(scans, rules);
        return Ok(new DecisionResponse(releaseId, result.score, result.level, result.decision, result.reason));
    }

    [HttpPost("ai/remediation")]
    public async Task<IActionResult> Remediation([FromBody] RemediationRequest request, CancellationToken cancellationToken)
    {
        // Send normalized finding metadata only. The API has no source-code or secret field.
        var response = await clients.CreateClient("ai-remediation").PostAsJsonAsync("/api/remediation", request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            HttpContext.RequestServices.GetRequiredService<ILogger<SecurityController>>()
                .LogWarning("AI remediation service returned {StatusCode}", (int)response.StatusCode);
            return Problem("AI remediation service is unavailable.", statusCode: StatusCodes.Status503ServiceUnavailable);
        }
        var body = await response.Content.ReadFromJsonAsync<RemediationResponse>(cancellationToken: cancellationToken);
        return body is null ? Problem("AI remediation returned an invalid response.", statusCode: 502) : Ok(body);
    }
}

public sealed record RemediationRequest(
    [property: Required, StringLength(80, MinimumLength = 1)] string Scanner,
    [property: Required, StringLength(160, MinimumLength = 1)] string FindingId,
    [property: Required, RegularExpression("^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")] string Severity,
    [property: StringLength(240)] string? FileLocation,
    [property: Required, StringLength(1200, MinimumLength = 1)] string Description,
    [property: StringLength(80)] string? CommitReference);
public sealed record RemediationResponse(string Explanation, string PotentialImpact, string SuggestedRemediation, IReadOnlyList<string> PreventionMeasures);
