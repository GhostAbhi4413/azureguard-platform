using System.ComponentModel.DataAnnotations;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace ApplicationLayer;

public sealed class PythonAiOptions
{
    public const string SectionName = "AI";
    public string BaseUrl { get; set; } = "http://localhost:8000";
    public int TimeoutSeconds { get; set; } = 25;
}

public sealed record RemediationRequest(
    [property: Required, StringLength(80, MinimumLength = 1)] string Scanner,
    [property: Required, StringLength(160, MinimumLength = 1)] string FindingId,
    [property: Required, RegularExpression("^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")] string Severity,
    [property: StringLength(240)] string? FileLocation,
    [property: Required, StringLength(1200, MinimumLength = 1)] string Description,
    [property: StringLength(80)] string? CommitReference);

public sealed record RemediationResponse(string Explanation, string PotentialImpact, string SuggestedRemediation, IReadOnlyList<string> PreventionMeasures);

public interface IAiRemediationService
{
    Task<RemediationResponse> ExplainAsync(RemediationRequest finding, CancellationToken cancellationToken);
}

public sealed class AiRemediationUnavailableException(string message, Exception? innerException = null) : Exception(message, innerException);

public sealed class PythonAiRemediationService(HttpClient httpClient, IOptions<PythonAiOptions> options, ILogger<PythonAiRemediationService> logger) : IAiRemediationService
{
    private static readonly Regex SecretPattern = new(
        @"(?i)(api[_-]?key|secret|password|token|authorization)\s*[:=]\s*[^\s,;]+|Bearer\s+[A-Za-z0-9._~+/-]+=*",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SourcePattern = new(
        @"(?im)^\s*(?:using|import|namespace|class|def|function)\s+|\b(?:const|let|var)\s+\w+\s*=|\b(?:SELECT|INSERT|UPDATE|DELETE)\s+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly PythonAiOptions _options = options.Value;

    public async Task<RemediationResponse> ExplainAsync(RemediationRequest finding, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(_options.BaseUrl, UriKind.Absolute, out var baseUri))
            throw new AiRemediationUnavailableException("AI remediation service is not configured.");

        // Only normalized finding metadata is sent. Common credential patterns in scanner text are redacted.
        var safeFinding = new
        {
            finding.Scanner,
            finding.FindingId,
            finding.Severity,
            FileLocation = Redact(finding.FileLocation),
            Description = Redact(finding.Description),
            CommitReference = Redact(finding.CommitReference)
        };
        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                using var response = await httpClient.PostAsJsonAsync(new Uri(baseUri, "/api/remediation"), safeFinding, cancellationToken);
                if ((int)response.StatusCode == 429 || (int)response.StatusCode >= 500)
                {
                    if (attempt == 0) { await Task.Delay(TimeSpan.FromMilliseconds(300), cancellationToken); continue; }
                }
                if (!response.IsSuccessStatusCode)
                {
                    logger.LogWarning("Python AI service returned HTTP {StatusCode}", (int)response.StatusCode);
                    throw new AiRemediationUnavailableException("AI remediation service could not provide guidance.");
                }
                var result = await response.Content.ReadFromJsonAsync<RemediationResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web), cancellationToken);
                if (result is null || string.IsNullOrWhiteSpace(result.Explanation) || string.IsNullOrWhiteSpace(result.PotentialImpact) || string.IsNullOrWhiteSpace(result.SuggestedRemediation) || result.PreventionMeasures is null)
                    throw new AiRemediationUnavailableException("AI remediation service returned an invalid response.");
                return result;
            }
            catch (AiRemediationUnavailableException) { throw; }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new AiRemediationUnavailableException("AI remediation service request timed out.", ex);
            }
            catch (HttpRequestException ex)
            {
                logger.LogWarning("Python AI service request failed ({StatusCode})", ex.StatusCode is null ? "network" : ((int)ex.StatusCode.Value).ToString());
                throw new AiRemediationUnavailableException("AI remediation service is temporarily unavailable.", ex);
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or IndexOutOfRangeException or InvalidOperationException)
            {
                logger.LogWarning("Python AI service response did not match the remediation contract.");
                throw new AiRemediationUnavailableException("AI remediation service returned an invalid response.", ex);
            }
        }
        throw new AiRemediationUnavailableException("AI remediation service is temporarily unavailable.");
    }

    private static string? Redact(string? value)
    {
        if (value is null) return null;
        var safe = SecretPattern.Replace(value, "[REDACTED]");
        // Scanner descriptions should be concise metadata. Drop multiline or code-like text rather than transmitting source snippets.
        return safe.Contains('\n') || safe.Contains('\r') || SourcePattern.IsMatch(safe)
            ? "[scanner description omitted because it contains source-like content]"
            : safe;
    }
}
