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
public sealed class SecurityController(AppDbContext db, RiskPolicyEngine engine, IAiRemediationService aiRemediation) : ControllerBase
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
        var findings = await db.ScanFindings.AsNoTracking().Where(x => x.ReleaseId == releaseId).ToListAsync(cancellationToken);
        var rules = await db.PolicyRules.AsNoTracking().Where(x => x.IsActive && db.Policies.Any(p => p.Id == x.PolicyId && p.ProjectId == release.ProjectId && p.IsActive)).ToListAsync(cancellationToken);
        var result = engine.Evaluate(scans, rules, findings.Count == 0 ? null : findings);
        return Ok(new DecisionResponse(releaseId, result.score, result.level, result.decision, result.reason));
    }

    [HttpPost("ai/remediation")]
    public async Task<IActionResult> Remediation([FromBody] RemediationRequest request, CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await aiRemediation.ExplainAsync(request, cancellationToken));
        }
        catch (AiRemediationUnavailableException)
        {
            return Problem("AI remediation is temporarily unavailable.", statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }
}
