using BusinessLayer;
using CoreModels;
using Xunit;

namespace BusinessLayer.Tests;

public class RiskPolicyEngineTests
{
    private readonly RiskPolicyEngine _engine = new();

    [Fact]
    public void CriticalFindingIsBlocked()
    {
        var result = _engine.Evaluate([new ScanResult { CriticalCount = 1 }]);
        Assert.Equal(Statuses.Blocked, result.decision);
    }

    [Fact]
    public void SmallNoncriticalFindingIsApproved()
    {
        var result = _engine.Evaluate([new ScanResult { LowCount = 1 }]);
        Assert.Equal(Statuses.Approved, result.decision);
    }

    [Fact]
    public void DuplicateNormalizedFindingOnlyCountsOnce()
    {
        var scans = new[] { new ScanResult { CriticalCount = 1 }, new ScanResult { CriticalCount = 1 } };
        var findings = new[] {
            new ScanFinding { Fingerprint = "same", Severity = "HIGH" },
            new ScanFinding { Fingerprint = "same", Severity = "HIGH" }
        };
        var result = _engine.Evaluate(scans, findings: findings);
        Assert.Equal(6m, result.score);
        Assert.Equal(Statuses.Approved, result.decision);
    }

    [Fact]
    public void FailedScannerRequiresReview()
    {
        var result = _engine.Evaluate([new ScanResult { Status = "FAILED" }]);
        Assert.Equal(Statuses.ManualReview, result.decision);
    }

    [Fact]
    public void SensitiveGitDiffRequiresReviewEvenWithOnlyOneHighFinding()
    {
        var result = _engine.Evaluate(
            [new ScanResult { ScanType = "GIT_DIFF", HighCount = 1 }],
            findings: [new ScanFinding { ScanType = "GIT_DIFF", Severity = "HIGH", RuleId = "GIT_DIFF_SENSITIVE_PATH" }]);

        Assert.Equal(Statuses.ManualReview, result.decision);
        Assert.Contains("Git diff", result.reason);
    }
}
