using System.Net;
using System.Text;
using System.Text.Json;
using ApplicationLayer;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace BusinessLayer.Tests;

public sealed class AzureOpenAiRemediationTests
{
    [Fact]
    public async Task SendsRedactedFindingAndReturnsStructuredGuidance()
    {
        string? captured = null;
        string? capturedKey = null;
        var responseContent = JsonSerializer.Serialize(new RemediationResponse("A token was found.", "Account access.", "Rotate it.", ["Use a secret store."]));
        var payload = JsonSerializer.Serialize(new { choices = new[] { new { message = new { content = responseContent } } } });
        var handler = new StubHandler((request, _) =>
        {
            captured = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            capturedKey = request.Headers.GetValues("api-key").Single();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(payload, Encoding.UTF8, "application/json") });
        });
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
        var service = new AzureOpenAiRemediationService(client, Options.Create(new AzureOpenAiOptions
        {
            Endpoint = "https://example.test", ApiKey = "unit-test-key", Deployment = "test-deployment"
        }), loggerFactory.CreateLogger<AzureOpenAiRemediationService>());

        var result = await service.ExplainAsync(new RemediationRequest("GITLEAKS", "rule-1", "CRITICAL", "appsettings.json", "token=do-not-send", null), CancellationToken.None);

        Assert.Equal("Rotate it.", result.SuggestedRemediation);
        Assert.Contains("[REDACTED]", captured);
        Assert.DoesNotContain("do-not-send", captured);
        Assert.Equal("unit-test-key", capturedKey);
        Assert.Contains("test-deployment", handler.LastRequestUri);
    }

    [Fact]
    public async Task ProviderErrorsBecomeSafeUnavailableException()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("private provider detail")
        }));
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var service = new AzureOpenAiRemediationService(new HttpClient(handler), Options.Create(new AzureOpenAiOptions
        {
            Endpoint = "https://example.test", ApiKey = "unit-test-key", Deployment = "test-deployment"
        }), loggerFactory.CreateLogger<AzureOpenAiRemediationService>());

        var exception = await Assert.ThrowsAsync<AiRemediationUnavailableException>(() => service.ExplainAsync(
            new RemediationRequest("TRIVY", "CVE-TEST", "HIGH", null, "Demo finding", null), CancellationToken.None));
        Assert.DoesNotContain("private provider detail", exception.Message);
    }

    [Fact]
    public async Task OmitsMultilineSourceLikeScannerText()
    {
        string? captured = null;
        var responseContent = JsonSerializer.Serialize(new RemediationResponse("Explanation", "Impact", "Fix", ["Prevent"]));
        var payload = JsonSerializer.Serialize(new { choices = new[] { new { message = new { content = responseContent } } } });
        var handler = new StubHandler((request, _) =>
        {
            captured = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(payload, Encoding.UTF8, "application/json") });
        });
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var service = new AzureOpenAiRemediationService(new HttpClient(handler), Options.Create(new AzureOpenAiOptions
        {
            Endpoint = "https://example.test", ApiKey = "unit-test-key", Deployment = "test-deployment"
        }), loggerFactory.CreateLogger<AzureOpenAiRemediationService>());

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
