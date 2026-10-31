using System.ComponentModel.DataAnnotations;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace ApplicationLayer;

public sealed class AzureOpenAiOptions
{
    public const string SectionName = "AzureOpenAI";
    public string Endpoint { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public string Deployment { get; set; } = "";
    public string ApiVersion { get; set; } = "2024-10-21";
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

public sealed class AzureOpenAiRemediationService(HttpClient httpClient, IOptions<AzureOpenAiOptions> options, ILogger<AzureOpenAiRemediationService> logger) : IAiRemediationService
{
    private static readonly Regex SecretPattern = new(
        @"(?i)(api[_-]?key|secret|password|token|authorization)\s*[:=]\s*[^\s,;]+|Bearer\s+[A-Za-z0-9._~+/-]+=*",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SourcePattern = new(
        @"(?im)^\s*(?:using|import|namespace|class|def|function)\s+|\b(?:const|let|var)\s+\w+\s*=|\b(?:SELECT|INSERT|UPDATE|DELETE)\s+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly AzureOpenAiOptions _options = options.Value;

    public async Task<RemediationResponse> ExplainAsync(RemediationRequest finding, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(_options.Endpoint, UriKind.Absolute, out var endpoint) || string.IsNullOrWhiteSpace(_options.ApiKey) || string.IsNullOrWhiteSpace(_options.Deployment))
            throw new AiRemediationUnavailableException("Azure OpenAI is not configured.");

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
        var url = $"{endpoint.ToString().TrimEnd('/')}/openai/deployments/{Uri.EscapeDataString(_options.Deployment)}/chat/completions?api-version={Uri.EscapeDataString(_options.ApiVersion)}";
        var payload = new
        {
            temperature = 0.2,
            response_format = new { type = "json_object" },
            messages = new object[]
            {
                new { role = "system", content = "You are a defensive security assistant. Return only a JSON object with string fields explanation, potentialImpact, suggestedRemediation, and an array of string preventionMeasures. Use only the provided sanitized finding metadata. Never request source code or secrets." },
                new { role = "user", content = JsonSerializer.Serialize(safeFinding) }
            }
        };

        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.TryAddWithoutValidation("api-key", _options.ApiKey);
                request.Content = JsonContent.Create(payload);
                using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if ((int)response.StatusCode == 429 || (int)response.StatusCode >= 500)
                {
                    if (attempt == 0) { await Task.Delay(TimeSpan.FromMilliseconds(300), cancellationToken); continue; }
                }
                if (!response.IsSuccessStatusCode)
                {
                    logger.LogWarning("Azure OpenAI returned HTTP {StatusCode}", (int)response.StatusCode);
                    throw new AiRemediationUnavailableException("Azure OpenAI could not provide remediation guidance.");
                }
                using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
                var content = document.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
                var result = JsonSerializer.Deserialize<RemediationResponse>(content ?? "", new JsonSerializerOptions(JsonSerializerDefaults.Web));
                if (result is null || string.IsNullOrWhiteSpace(result.Explanation) || string.IsNullOrWhiteSpace(result.PotentialImpact) || string.IsNullOrWhiteSpace(result.SuggestedRemediation) || result.PreventionMeasures is null)
                    throw new AiRemediationUnavailableException("Azure OpenAI returned an invalid remediation response.");
                return result;
            }
            catch (AiRemediationUnavailableException) { throw; }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new AiRemediationUnavailableException("Azure OpenAI request timed out.", ex);
            }
            catch (HttpRequestException ex)
            {
                logger.LogWarning("Azure OpenAI request failed ({StatusCode})", ex.StatusCode is null ? "network" : ((int)ex.StatusCode.Value).ToString());
                throw new AiRemediationUnavailableException("Azure OpenAI is temporarily unavailable.", ex);
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or IndexOutOfRangeException or InvalidOperationException)
            {
                logger.LogWarning("Azure OpenAI response did not match the remediation contract.");
                throw new AiRemediationUnavailableException("Azure OpenAI returned an invalid remediation response.", ex);
            }
        }
        throw new AiRemediationUnavailableException("Azure OpenAI is temporarily unavailable.");
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
