using System.Net;
using System.Text;
using System.Text.Json;
using ApplicationLayer;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace BusinessLayer.Tests;

public sealed class PythonAiRemediationTests
{
    [Fact]
    public async Task ForwardsRedactedFindingToPythonServiceAndReturnsStructuredGuidance()
    {
        string? captured = null;
        string? capturedKey = null;
        var payload = JsonSerializer.Serialize(new RemediationResponse("A token was found.", "Account access.", "Rotate it.", ["Use a secret store."]), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var handler = new StubHandler((request, _) =>
        {
            captured = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            capturedKey = request.Headers.TryGetValues("api-key", out var apiKeys) ? apiKeys.Single() : null;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(payload, Encoding.UTF8, "application/json") });
        });
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
        var service = new PythonAiRemediationService(client, Options.Create(new PythonAiOptions
        {
            BaseUrl = "http://ai-service:8000"
        }), loggerFactory.CreateLogger<PythonAiRemediationService>());

        var result = await service.ExplainAsync(new RemediationRequest("GITLEAKS", "rule-1", "CRITICAL", "appsettings.json", "token=do-not-send", null), CancellationToken.None);

        Assert.Equal("Rotate it.", result.SuggestedRemediation);
        Assert.Contains("[REDACTED]", captured);
        Assert.DoesNotContain("do-not-send", captured);
        Assert.Null(capturedKey);
        Assert.Contains("http://ai-service:8000/api/remediation", handler.LastRequestUri);
        Assert.Contains("\"findingId\"", captured);
    }

    [Fact]
    public async Task PythonServiceErrorsBecomeSafeUnavailableException()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("private provider detail")
        }));
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var service = new PythonAiRemediationService(new HttpClient(handler), Options.Create(new PythonAiOptions
        {
            BaseUrl = "http://ai-service:8000"
        }), loggerFactory.CreateLogger<PythonAiRemediationService>());

        var exception = await Assert.ThrowsAsync<AiRemediationUnavailableException>(() => service.ExplainAsync(
            new RemediationRequest("TRIVY", "CVE-TEST", "HIGH", null, "Demo finding", null), CancellationToken.None));
        Assert.DoesNotContain("private provider detail", exception.Message);
    }

    [Fact]
    public async Task OmitsMultilineSourceLikeScannerText()
    {
        string? captured = null;
        var payload = JsonSerializer.Serialize(new RemediationResponse("Explanation", "Impact", "Fix", ["Prevent"]), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var handler = new StubHandler((request, _) =>
        {
            captured = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(payload, Encoding.UTF8, "application/json") });
        });
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var service = new PythonAiRemediationService(new HttpClient(handler), Options.Create(new PythonAiOptions
        {
            BaseUrl = "http://ai-service:8000"
        }), loggerFactory.CreateLogger<PythonAiRemediationService>());

        await service.ExplainAsync(new RemediationRequest("SAST", "rule-2", "MEDIUM", "source.cs", "private source\nclass SecretCode {}", null), CancellationToken.None);

        Assert.DoesNotContain("private source", captured);
        Assert.Contains("scanner description omitted", captured);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder) : HttpMessageHandler
    {
        public string? LastRequestUri { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri?.ToString();
            return responder(request, cancellationToken);
        }
    }
}
