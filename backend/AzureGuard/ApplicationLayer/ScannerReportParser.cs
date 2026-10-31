using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using CoreModels;

namespace ApplicationLayer;

public sealed class ScannerReportParser
{
    private static readonly GitDiffAnalyzer DiffAnalyzer = new();

    public IngestScanRequest Parse(ScanReportRequest request)
    {
        var type = request.ScanType.Trim().ToUpperInvariant();
        var tool = request.ToolName.Trim().ToUpperInvariant();
        if (tool == "GIT_DIFF") return ParseGitDiff(type, request.Status, request.Report);
        if (tool is "GITLEAKS" or "TRIVY" or "CHECKOV" or "SONARQUBE") return ParseJson(type, tool, request.Status, request.Report);
        if (tool is "JUNIT" or "DOTNET_TEST" or "TEST") return ParseJUnit(type, tool, request.Status, request.Report);
        throw new ArgumentException($"Unsupported scanner report: {request.ToolName}.");
    }

    private static IngestScanRequest ParseGitDiff(string type, string status, string patch)
    {
        var findings = DiffAnalyzer.Analyze(patch).Select(x => new FindingRequest(
            type, "HIGH", x.RuleId, x.Title,
            "A security-sensitive file or control changed in this commit. Review the change before release.",
            x.FilePath, null, x.Fingerprint)).ToList();
        // Never persist the patch: it can contain proprietary code or credentials.
        var summary = JsonSerializer.Serialize(new { analyzedFileCount = DiffAnalyzer.CountFiles(patch), findingCount = findings.Count });
        return Build(type, "GIT_DIFF", status, summary, findings);
    }

    private static IngestScanRequest ParseJson(string type, string tool, string status, string raw)
    {
        using var doc = JsonDocument.Parse(raw);
        var fs = new List<FindingRequest>();
        if (tool == "GITLEAKS" && doc.RootElement.ValueKind == JsonValueKind.Array)
            foreach (var x in doc.RootElement.EnumerateArray()) fs.Add(new(type, "CRITICAL", Get(x, "RuleID"), Get(x, "Description"), "Potential secret detected", Get(x, "File"), GetInt(x, "StartLine"), Get(x, "Fingerprint")));
        if (tool == "TRIVY" && doc.RootElement.TryGetProperty("Results", out var rs))
            foreach (var result in rs.EnumerateArray()) if (result.TryGetProperty("Vulnerabilities", out var vs)) foreach (var x in vs.EnumerateArray()) fs.Add(new(type, Map(Get(x, "Severity")), Get(x, "VulnerabilityID"), Get(x, "Title"), Get(x, "Description"), Get(result, "Target"), null, Get(x, "PrimaryURL")));
        if (tool == "CHECKOV" && doc.RootElement.TryGetProperty("results", out var cr) && cr.TryGetProperty("failed_checks", out var failed))
            foreach (var x in failed.EnumerateArray()) fs.Add(new(type, Map(Get(x, "severity")), Get(x, "check_id"), Get(x, "check_name"), Get(x, "check_name"), Get(x, "file_path"), GetInt(x, "file_line_range"), Get(x, "guideline")));
        if (tool == "SONARQUBE" && doc.RootElement.TryGetProperty("issues", out var issues))
            foreach (var x in issues.EnumerateArray()) fs.Add(new(type, Map(Get(x, "severity")), Get(x, "rule"), Get(x, "message"), Get(x, "message"), Get(x, "component"), GetInt(x, "line"), null));
        return Build(type, tool, status, raw, fs);
    }

    private static IngestScanRequest ParseJUnit(string type, string tool, string status, string raw)
    {
        var root = XDocument.Parse(raw).Root;
        var fs = root?.Descendants("failure").Select(x => new FindingRequest(type, "HIGH", null, "Test failure", x.Value, x.Parent?.Attribute("classname")?.Value, null, null)).ToList() ?? [];
        return Build(type, tool, status, raw, fs);
    }

    private static IngestScanRequest Build(string type, string tool, string status, string raw, List<FindingRequest> fs) =>
        new(type, tool, status, fs.Count(x => x.Severity == "CRITICAL"), fs.Count(x => x.Severity == "HIGH"), fs.Count(x => x.Severity == "MEDIUM"), fs.Count(x => x.Severity == "LOW"), fs.Count(x => x.Severity == "INFO"), raw, null, fs);

    private static string Map(string? value) => value?.ToUpperInvariant() switch { "BLOCKER" or "CRITICAL" => "CRITICAL", "HIGH" or "MAJOR" => "HIGH", "MEDIUM" or "MODERATE" or "MINOR" => "MEDIUM", "LOW" => "LOW", _ => "INFO" };
    private static string? Get(JsonElement x, string n) => x.TryGetProperty(n, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString() : null;
    private static int? GetInt(JsonElement x, string n) { if (!x.TryGetProperty(n, out var v)) return null; if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n1)) return n1; if (v.ValueKind == JsonValueKind.Array && v.GetArrayLength() > 0 && v[0].TryGetInt32(out n1)) return n1; return null; }
}

public sealed class GitDiffAnalyzer
{
    private static readonly string[] SensitivePathPatterns = [
        @"(^|/)(\.env(\..*)?|secrets?)(/|$)", @"(^|/)(auth|authentication|authorization|security|policy)(/|$)",
        @"(^|/)\.github/workflows(/|$)", @"(^|/)(dockerfile|docker-compose[^/]*|.*\.tf|.*\.ya?ml|.*\.pem|.*\.key|.*\.pfx)$",
        @"(^|/)(appsettings[^/]*\.json|nuget\.config|web\.config)$"
    ];
    private static readonly (string Rule, string Pattern)[] RiskyAdditions = [
        ("GIT_DIFF_AUTH_DISABLED", @"(?i)(AllowAnonymous|SkipAuthorization|DisableAuthentication|RequireAuthorization\s*\(\s*false|auth(?:entication|orization)?\s*[:=]\s*(?:false|none|disabled))"),
        ("GIT_DIFF_TLS_DISABLED", @"(?i)(ValidateIssuer\s*=\s*false|RequireHttpsMetadata\s*=\s*false|DangerousAcceptAnyServerCertificate|verify(?:_ssl)?\s*[:=]\s*false|tls\s*[:=]\s*(?:false|disabled))"),
        ("GIT_DIFF_PUBLIC_ACCESS", @"(?i)(0\.0\.0\.0/0|publicly_accessible\s*=\s*true|public[_ -]?access\s*[:=]\s*true|privileged\s*[:=]\s*true)"),
        ("GIT_DIFF_SECURITY_SCAN_DISABLED", @"(?i)(gitleaks|trivy|sonar|security[_ -]?scan).{0,60}(?:disabled|false|continue-on-error\s*:\s*true)")
    ];
    private static readonly (string Rule, string Pattern)[] RiskyRemovals = [
        ("GIT_DIFF_AUTH_REMOVED", @"(?i)(\[Authorize(?:\([^\]]*\))?\]|\.RequireAuthorization\s*\(|ValidateIssuer\s*=\s*true|RequireHttpsMetadata\s*=\s*true)"),
        ("GIT_DIFF_SECURITY_SCAN_REMOVED", @"(?i)(gitleaks|trivy|sonar|security[_ -]?scan)")
    ];

    public IReadOnlyList<GitDiffFinding> Analyze(string patch)
    {
        if (patch.Length > 2_000_000) throw new ArgumentException("Git diff report exceeds the 2 MB limit.");
        var results = new Dictionary<string, GitDiffFinding>(StringComparer.OrdinalIgnoreCase);
        string? currentPath = null;
        string? deletedPath = null;
        foreach (var line in patch.Split('\n'))
        {
            if (line.StartsWith("--- a/", StringComparison.Ordinal)) deletedPath = NormalizePath(line[6..].TrimEnd('\r'));
            if (line.StartsWith("+++ b/", StringComparison.Ordinal))
            {
                currentPath = NormalizePath(line[6..].TrimEnd('\r'));
                deletedPath = null;
                if (currentPath == "/dev/null") currentPath = null;
                if (currentPath is not null && SensitivePathPatterns.Any(p => System.Text.RegularExpressions.Regex.IsMatch(currentPath, p, System.Text.RegularExpressions.RegexOptions.IgnoreCase)))
                    Add(results, "GIT_DIFF_SENSITIVE_PATH", currentPath);
            }
            else if (line.StartsWith("+++ /dev/null", StringComparison.Ordinal) && deletedPath is not null)
            {
                currentPath = deletedPath;
                if (SensitivePathPatterns.Any(p => System.Text.RegularExpressions.Regex.IsMatch(currentPath, p, System.Text.RegularExpressions.RegexOptions.IgnoreCase)))
                    Add(results, "GIT_DIFF_SENSITIVE_PATH", currentPath);
            }
            else if (currentPath is not null && line.StartsWith('+') && !line.StartsWith("+++", StringComparison.Ordinal))
            {
                foreach (var (rule, pattern) in RiskyAdditions)
                    if (System.Text.RegularExpressions.Regex.IsMatch(line[1..], pattern)) Add(results, rule, currentPath);
            }
            else if (currentPath is not null && line.StartsWith('-') && !line.StartsWith("---", StringComparison.Ordinal))
            {
                foreach (var (rule, pattern) in RiskyRemovals)
                    if (System.Text.RegularExpressions.Regex.IsMatch(line[1..], pattern)) Add(results, rule, currentPath);
            }
        }
        return results.Values.ToArray();
    }

    public int CountFiles(string patch) => patch.Split('\n').Count(x => x.StartsWith("+++ b/", StringComparison.Ordinal));
    private static string NormalizePath(string path) => path.Replace('\\', '/').TrimStart('/').Replace("../", "");
    private static void Add(IDictionary<string, GitDiffFinding> items, string rule, string path)
    {
        var id = $"{rule}|{path}";
        if (items.ContainsKey(id)) return;
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(id))).ToLowerInvariant();
        items[id] = new GitDiffFinding(rule, rule == "GIT_DIFF_SENSITIVE_PATH" ? "Security-sensitive file changed" : "Potentially unsafe security control added", path, fingerprint);
    }
}

public sealed record GitDiffFinding(string RuleId, string Title, string FilePath, string Fingerprint);
