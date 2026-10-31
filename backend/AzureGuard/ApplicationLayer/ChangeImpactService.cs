using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using CoreModels;
using DataAccessLayer;
using Microsoft.EntityFrameworkCore;

namespace ApplicationLayer;

public sealed record SanitizedChangeContext(string? CommitReference, IReadOnlyList<string> Files, string Diff);
public sealed record StoredChangeImpactResponse(long ReleaseId, string? CommitReference, string Status, string? PotentialRisk,
    string? Explanation, IReadOnlyList<ChangeEvidence> Evidence, string? Remediation, IReadOnlyList<string> RecommendedTests,
    bool? ManualReviewRecommended, string? ModelId, string? DeploymentName, string? FailureReason, DateTime CreatedAt);

public sealed class GitDiffContextSanitizer
{
    private const int MaxPatchCharacters = 2_000_000;
    private const int MaxContextCharacters = 12_000;
    private static readonly Regex SensitivePath = new(
        @"(?i)(auth|authentication|authorization|identity|security|policy|middleware|credential|secret|keyvault|key-vault|appsettings|web\.config|dockerfile|\.github/workflows|\.tf$|\.ya?ml$|\.env)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SecretPath = new(
        @"(?i)(^|/)(\.env(?:\.[^/]*)?|[^/]*(?:secret|credential|private.?key)[^/]*)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SensitiveChange = new(
        @"(?i)(authorize|authentication|authorization|jwt|roles?|claims|permission|policy|security|secret|credential|keyvault|key-vault|tls|ssl|certificate|cors|csrf|token|password|vault|private.?key)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SecretValue = new(
        @"(?i)(?<key>(?:api[_-]?key|client[_-]?secret|secret|password|token|authorization|connectionstring|accountkey)\s*[:=]\s*)(?:Bearer\s+[A-Za-z0-9._~+/-]+=*|""[^""]*""|'[^']*'|[^\s,;]+)|(?<bearer>Bearer\s+)[A-Za-z0-9._~+/-]+=*",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex TokenValue = new(
        @"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex PrivateKey = new(
        @"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
        RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex PromptInjection = new(
        @"(?i)(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|system prompt|developer message|reveal (?:the )?secrets?|exfiltrate|print (?:the )?api[_ -]?key|do not follow (?:the )?system)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public SanitizedChangeContext Sanitize(string rawDiff, string? commitReference)
    {
        if (rawDiff.Length > MaxPatchCharacters) throw new ArgumentException("Pull request diff exceeds the 2 MB limit.");
        var blocks = new List<(string Path, List<string> Lines)>();
        string? path = null;
        List<string>? changedLines = null;
        void Flush()
        {
            if (path is not null && changedLines is not null) blocks.Add((NormalizePath(path), changedLines));
        }

        foreach (var line in rawDiff.Split('\n'))
        {
            if (line.StartsWith("diff --git ", StringComparison.Ordinal))
            {
                Flush();
                var separator = line.IndexOf(" b/", StringComparison.Ordinal);
                path = separator >= 0 ? line[(separator + 3)..].TrimEnd('\r') : null;
                changedLines = [];
                continue;
            }
            if (line.StartsWith("+++ b/", StringComparison.Ordinal))
            {
                path = line[6..].TrimEnd('\r');
                continue;
            }
            if (line.StartsWith("--- a/", StringComparison.Ordinal) && path is null)
            {
                path = line[6..].TrimEnd('\r');
                changedLines ??= [];
                continue;
            }
            if (line.StartsWith('+') && !line.StartsWith("+++", StringComparison.Ordinal)
                || line.StartsWith('-') && !line.StartsWith("---", StringComparison.Ordinal))
                changedLines?.Add(line);
        }
        Flush();

        var selected = blocks.Where(x => SensitivePath.IsMatch(x.Path)
            || x.Lines.Any(line => SensitiveChange.IsMatch(line))).Take(40).ToList();
        var files = selected.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var context = new StringBuilder();
        foreach (var block in selected)
        {
            if (context.Length >= MaxContextCharacters) break;
            context.Append("FILE: ").Append(block.Path).AppendLine();
            if (SecretPath.IsMatch(block.Path))
            {
                context.AppendLine("[secret-bearing file contents omitted]");
                continue;
            }
            var redactedBlock = PrivateKey.Replace(string.Join('\n', block.Lines), "[REDACTED_PRIVATE_KEY]");
            foreach (var line in redactedBlock.Split('\n').Take(100))
            {
                var safe = SecretValue.Replace(line, match => match.Groups["key"].Success
                    ? match.Groups["key"].Value + "[REDACTED]"
                    : "Bearer [REDACTED]");
                safe = TokenValue.Replace(safe, "[REDACTED_TOKEN]");
                safe = PromptInjection.Replace(safe, "[untrusted instruction-like text omitted]");
                if (context.Length + safe.Length + Environment.NewLine.Length > MaxContextCharacters) break;
                context.AppendLine(safe[..Math.Min(safe.Length, 500)]);
            }
        }

        var reference = string.IsNullOrWhiteSpace(commitReference) || !Regex.IsMatch(commitReference, @"\A[A-Fa-f0-9]{7,80}\z")
            ? null : commitReference;
        return new SanitizedChangeContext(reference, files, context.ToString());
    }

    private static string NormalizePath(string value)
    {
        var normalized = value.Replace('\\', '/').TrimStart('/').Replace("../", "");
        return normalized[..Math.Min(normalized.Length, 240)];
    }
}

public sealed class ChangeImpactService(AppDbContext db, IAiRemediationService ai)
{
    public async Task<AIChangeImpactAnalysis> AnalyzeAndStoreAsync(long releaseId, SanitizedChangeContext context, CancellationToken cancellationToken)
    {
        var entity = new AIChangeImpactAnalysis
        {
            ReleaseId = releaseId,
            CommitReference = context.CommitReference,
            Status = "SKIPPED",
            FailureReason = "No security-sensitive changed files or lines were found."
        };
        if (context.Files.Count > 0 && !string.IsNullOrWhiteSpace(context.Diff))
        {
            try
            {
                var result = await ai.AnalyzeChangeImpactAsync(new ChangeImpactRequest(context.CommitReference, context.Files, context.Diff), cancellationToken);
                entity.Status = "AVAILABLE";
                entity.PotentialRisk = result.PotentialRisk;
                entity.Explanation = result.Explanation;
                entity.EvidenceJson = JsonSerializer.Serialize(result.Evidence);
                entity.Remediation = result.Remediation;
                entity.RecommendedTestsJson = JsonSerializer.Serialize(result.RecommendedTests);
                entity.ManualReviewRecommended = result.ManualReviewRecommended;
                entity.ModelId = result.ModelId;
                entity.DeploymentName = result.DeploymentName;
                entity.FailureReason = null;
            }
            catch (AiRemediationUnavailableException)
            {
                entity.Status = "UNAVAILABLE";
                entity.FailureReason = "Azure OpenAI analysis is unavailable or returned an invalid response.";
            }
        }
        db.AIChangeImpactAnalyses.Add(entity);
        await db.SaveChangesAsync(cancellationToken);
        return entity;
    }

    public Task<AIChangeImpactAnalysis?> GetLatestAsync(long releaseId, CancellationToken cancellationToken) =>
        db.AIChangeImpactAnalyses.AsNoTracking().Where(x => x.ReleaseId == releaseId)
            .OrderByDescending(x => x.CreatedAt).ThenByDescending(x => x.Id).FirstOrDefaultAsync(cancellationToken);

    public static StoredChangeImpactResponse ToResponse(AIChangeImpactAnalysis analysis) => new(
        analysis.ReleaseId, analysis.CommitReference, analysis.Status, analysis.PotentialRisk, analysis.Explanation,
        JsonSerializer.Deserialize<ChangeEvidence[]>(analysis.EvidenceJson ?? "[]") ?? [], analysis.Remediation,
        JsonSerializer.Deserialize<string[]>(analysis.RecommendedTestsJson ?? "[]") ?? [], analysis.ManualReviewRecommended,
        analysis.ModelId, analysis.DeploymentName, analysis.FailureReason, analysis.CreatedAt);
}
