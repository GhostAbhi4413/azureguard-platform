using CoreModels;
namespace BusinessLayer;
public record PolicyEvaluation(decimal score, string level, string decision, string reason, object features);
public class RiskPolicyEngine
{
    // Local project policy weights, not a published security standard.
    public PolicyEvaluation Evaluate(IEnumerable<ScanResult> scans, IEnumerable<PolicyRule>? rules = null, IEnumerable<ScanFinding>? findings = null)
    {
        var s = scans.ToList();
        // Prefer normalized findings and collapse repeated scanner reports by fingerprint or stable identity.
        var unique = findings?.GroupBy(f => !string.IsNullOrWhiteSpace(f.Fingerprint)
                ? f.Fingerprint : $"{f.ScanType}|{f.RuleId}|{f.FilePath}|{f.LineNumber}|{f.Severity}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First()).ToList();
        int Count(string severity, Func<ScanResult, int> fallback) => unique is null ? s.Sum(fallback) : unique.Count(x => x.Severity.Equals(severity, StringComparison.OrdinalIgnoreCase));
        int c = Count("CRITICAL", x => x.CriticalCount), h = Count("HIGH", x => x.HighCount), m = Count("MEDIUM", x => x.MediumCount), l = Count("LOW", x => x.LowCount);
        decimal score = Math.Min(100, c * 25 + h * 6 + m * 2 + l * .25m);
        var active = rules?.Where(x => x.IsActive).ToList() ?? [];
        var failed = s.Any(x => x.Status.Equals("FAILED", StringComparison.OrdinalIgnoreCase));
        var sensitiveDiff = unique?.Any(x => x.ScanType.Equals("GIT_DIFF", StringComparison.OrdinalIgnoreCase)) == true;
        var features = new { c, h, m, l, failed };
        if (active.Any(x => x.RuleCode == "SECRET" && s.Any(y => y.ScanType == "GITLEAKS" && y.CriticalCount > 0))) return new(100, "CRITICAL", Statuses.Blocked, "Leaked secret detected (SECRET policy)", features);
        if (c > 0) return new(Math.Max(score, 75), "CRITICAL", Statuses.Blocked, $"{c} critical finding(s) (critical hard-block policy)", features);
        if (failed) return new(score, "UNKNOWN", Statuses.ManualReview, "One or more scanners failed; release requires review", features);
        if (sensitiveDiff) return new(score, "MEDIUM", Statuses.ManualReview, "Security-sensitive Git diff changes require reviewer approval", features);
        if (score >= 75) return new(score, "HIGH", Statuses.Blocked, "Risk score is at least 75 (local weighted policy)", features);
        if (score >= 50 || h >= 5) return new(score, "MEDIUM", Statuses.ManualReview, "Risk score or high-severity findings require review (local weighted policy)", features);
        return new(score, "LOW", Statuses.Approved, "No blocking policy rule was triggered", features);
    }
}
