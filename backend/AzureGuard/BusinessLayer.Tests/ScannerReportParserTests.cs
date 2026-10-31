using ApplicationLayer;
using CoreModels;
using Xunit;

namespace BusinessLayer.Tests;

public sealed class ScannerReportParserTests
{
    private readonly ScannerReportParser _parser = new();

    [Fact]
    public void GitDiffDetectsSensitiveChangesAndDoesNotPersistPatchText()
    {
        const string patch = "diff --git a/.github/workflows/security.yml b/.github/workflows/security.yml\n+++ b/.github/workflows/security.yml\n@@ -1 +1 @@\n-gitleaks-action\n+gitleaks-action: disabled\n";
        var parsed = _parser.Parse(new ScanReportRequest("GIT_DIFF", "GIT_DIFF", "PASSED", patch));

        Assert.Equal("GIT_DIFF", parsed.ScanType);
        Assert.Contains(parsed.Findings!, x => x.RuleId == "GIT_DIFF_SENSITIVE_PATH");
        Assert.Contains(parsed.Findings!, x => x.RuleId == "GIT_DIFF_SECURITY_SCAN_DISABLED");
        Assert.DoesNotContain("gitleaks-action: disabled", parsed.RawSummaryJson);
    }

    [Fact]
    public void SonarQubeIssuesAreNormalizedForIngestion()
    {
        const string report = """{"issues":[{"severity":"BLOCKER","rule":"csharp:S123","message":"Do not disable validation","component":"project:src/File.cs","line":27}]}""";
        var parsed = _parser.Parse(new ScanReportRequest("SAST", "SONARQUBE", "PASSED", report));

        var issue = Assert.Single(parsed.Findings!);
        Assert.Equal("CRITICAL", issue.Severity);
        Assert.Equal("csharp:S123", issue.RuleId);
        Assert.Equal(27, issue.LineNumber);
        Assert.Equal(1, parsed.CriticalCount);
    }

    [Fact]
    public void OrdinaryCodeDiffDoesNotCreateSecurityFinding()
    {
        const string patch = "diff --git a/src/Widget.cs b/src/Widget.cs\n+++ b/src/Widget.cs\n+var greeting = \"hello\";\n";
        var parsed = _parser.Parse(new ScanReportRequest("GIT_DIFF", "GIT_DIFF", "PASSED", patch));

        Assert.Empty(parsed.Findings!);
    }

    [Fact]
    public void RemovalOfAuthorizationControlIsDetected()
    {
        const string patch = "diff --git a/src/RequestHandler.cs b/src/RequestHandler.cs\n--- a/src/RequestHandler.cs\n+++ b/src/RequestHandler.cs\n-[Authorize]\n public IActionResult Get() => Ok();\n";
        var parsed = _parser.Parse(new ScanReportRequest("GIT_DIFF", "GIT_DIFF", "PASSED", patch));

        Assert.Contains(parsed.Findings!, x => x.RuleId == "GIT_DIFF_AUTH_REMOVED");
    }
}
