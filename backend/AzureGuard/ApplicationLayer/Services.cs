using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BusinessLayer;
using CoreModels;
using DataAccessLayer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace ApplicationLayer;

public sealed class PasswordService
{
    public string Hash(string password) { using var random = RandomNumberGenerator.Create(); var salt = new byte[16]; random.GetBytes(salt); var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100000, HashAlgorithmName.SHA256, 32); return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}"; }
    public bool Verify(string password, string stored) { var parts = stored.Split('.'); if (parts.Length != 2) return false; var hash = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(parts[0]), 100000, HashAlgorithmName.SHA256, 32); return CryptographicOperations.FixedTimeEquals(hash, Convert.FromBase64String(parts[1])); }
}
public sealed class AuthService(AppDbContext db, IConfiguration configuration, PasswordService passwords)
{
    public async Task<AuthResponse?> Signup(SignupRequest r) { var email = r.Email.Trim().ToLowerInvariant(); if (await db.AppUsers.AnyAsync(x => x.Email == email)) return null; var role = string.IsNullOrWhiteSpace(r.RoleName) || !new[] { "Developer", "Reviewer", "Admin" }.Contains(r.RoleName, StringComparer.OrdinalIgnoreCase) ? "Developer" : r.RoleName!; var u = new AppUser { FullName = r.FullName.Trim(), Email = email, RoleName = role, PasswordHash = passwords.Hash(r.Password) }; db.AppUsers.Add(u); await db.SaveChangesAsync(); return Token(u); }
    public async Task<AuthResponse?> Login(LoginRequest r) { var u = await db.AppUsers.SingleOrDefaultAsync(x => x.Email == r.Email.Trim().ToLowerInvariant() && x.IsActive); return u is null || !passwords.Verify(r.Password, u.PasswordHash) ? null : Token(u); }
    private AuthResponse Token(AppUser u) { var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!)); var t = new JwtSecurityToken(configuration["Jwt:Issuer"], configuration["Jwt:Audience"], [new Claim(ClaimTypes.NameIdentifier, u.Id.ToString()), new Claim(ClaimTypes.Email, u.Email), new Claim(ClaimTypes.Role, u.RoleName)], expires: DateTime.UtcNow.AddHours(8), signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)); return new(u.Id, u.FullName, u.Email, u.RoleName, new JwtSecurityTokenHandler().WriteToken(t)); }
}
public sealed class ReleaseService(AppDbContext db, RiskPolicyEngine engine, ScannerReportParser reports)
{
    public Task<DecisionResponse?> IngestReport(long id, ScanReportRequest request, long? userId = null) => Ingest(id, reports.Parse(request), userId);
    public async Task<DecisionResponse?> Ingest(long id, IngestScanRequest r, long? userId = null) { var rel = await db.Releases.FindAsync(id); if (rel is null) return null; var scanType = r.ScanType.Trim().ToUpperInvariant(); var status = r.Status.Trim().ToUpperInvariant(); if (!new[] { "SAST", "DAST", "SCA", "CONTAINER", "GITLEAKS", "IAC", "TEST" }.Contains(scanType) || !new[] { "PASSED", "FAILED", "WARNING" }.Contains(status)) throw new ArgumentException("Unsupported scan type or status."); if (new[] { r.CriticalCount, r.HighCount, r.MediumCount, r.LowCount, r.InfoCount }.Any(x => x < 0)) throw new ArgumentException("Finding counts cannot be negative."); if (rel.Status is Statuses.Approved or Statuses.Blocked) throw new InvalidOperationException("This release has already reached a terminal decision."); var scan = new ScanResult { ReleaseId = id, ScanType = scanType, ToolName = r.ToolName.Trim(), Status = status, CriticalCount = r.CriticalCount, HighCount = r.HighCount, MediumCount = r.MediumCount, LowCount = r.LowCount, InfoCount = r.InfoCount, RawSummaryJson = r.RawSummaryJson, ReportUrl = r.ReportUrl }; db.ScanResults.Add(scan); foreach (var f in r.Findings ?? []) { var severity = f.Severity.Trim().ToUpperInvariant(); if (!new[] { "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }.Contains(severity)) throw new ArgumentException("Unsupported finding severity."); db.ScanFindings.Add(new ScanFinding { ReleaseId = id, ScanResult = scan, ScanType = scanType, Severity = severity, RuleId = f.RuleId, Title = f.Title, Description = f.Description, FilePath = f.FilePath, LineNumber = f.LineNumber, Fingerprint = f.Fingerprint }); } await db.SaveChangesAsync(); var rules = await db.PolicyRules.Where(x => x.IsActive && db.Policies.Any(p => p.Id == x.PolicyId && p.ProjectId == rel.ProjectId && p.IsActive)).ToListAsync(); var e = engine.Evaluate(await db.ScanResults.Where(x => x.ReleaseId == id).ToListAsync(), rules); db.RiskScores.Add(new RiskScore { ReleaseId = id, Score = e.score, RiskLevel = e.level, FeatureJson = JsonSerializer.Serialize(e.features), PredictionReason = e.reason }); db.PolicyDecisions.Add(new PolicyDecision { ReleaseId = id, RiskScore = e.score, Decision = e.decision, DecisionReason = e.reason }); rel.Status = e.decision; rel.CompletedAt = DateTime.UtcNow; db.AuditLogs.Add(new AuditLog { UserId = userId, ReleaseId = id, Action = "SCAN_INGESTED_AND_DECIDED", DetailsJson = JsonSerializer.Serialize(new { scanType, e.score, e.decision }) }); await db.SaveChangesAsync(); return new(id, e.score, e.level, e.decision, e.reason); }
}
