using System.Net.Http.Headers;
using System.Text.Json;

namespace ApplicationLayer;

public record RepositoryAnalysis(string TechStack, string? BuildCommand, string? TestCommand, string DockerfilePath, string? HelmChartPath, IReadOnlyList<string> DetectedFiles);

public sealed class RepositoryAnalyzer(HttpClient http)
{
    public async Task<RepositoryAnalysis> AnalyzeAsync(string repositoryUrl, string branch, CancellationToken cancellationToken = default)
    {
        var files = await GetFilesAsync(repositoryUrl, branch, cancellationToken);
        var names = files.Select(Path.GetFileName).Where(x => x is not null).Select(x => x!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var all = files.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var stack = names.Any(x => x.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || x.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)) ? "DOTNET" : names.Contains("pom.xml") || names.Contains("build.gradle") || names.Contains("build.gradle.kts") ? "JAVA" : names.Contains("package.json") ? "NODE" : names.Contains("requirements.txt") || names.Contains("pyproject.toml") ? "PYTHON" : names.Contains("Gemfile") ? "RUBY" : names.Contains("go.mod") ? "GO" : "OTHER";
        var build = stack switch { "DOTNET" => "dotnet build --configuration Release", "JAVA" when names.Contains("pom.xml") => "mvn clean package", "JAVA" => "./gradlew build", "NODE" => "npm run build", "PYTHON" => "python -m compileall .", "RUBY" => "bundle exec rake", "GO" => "go build ./...", _ => null };
        var test = stack switch { "DOTNET" => "dotnet test --configuration Release", "JAVA" when names.Contains("pom.xml") => "mvn test", "JAVA" => "./gradlew test", "NODE" => "npm test", "PYTHON" => "pytest", "RUBY" => "bundle exec rspec", "GO" => "go test ./...", _ => null };
        return new(stack, build, test, all.FirstOrDefault(x => x.EndsWith("Dockerfile", StringComparison.OrdinalIgnoreCase)) ?? "./Dockerfile", all.FirstOrDefault(x => x.StartsWith("helm", StringComparison.OrdinalIgnoreCase) && x.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)), files);
    }

    private async Task<IReadOnlyList<string>> GetFilesAsync(string url, string branch, CancellationToken cancellationToken)
    {
        var uri = new Uri(url); var parts = uri.AbsolutePath.Trim('/').Replace(".git", "").Split('/');
        if (!uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) || parts.Length < 2) return [];
        http.DefaultRequestHeaders.UserAgent.Clear(); http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("AzureGuard", "1.0"));
        using var response = await http.GetAsync($"https://api.github.com/repos/{parts[0]}/{parts[1]}/git/trees/{Uri.EscapeDataString(branch)}?recursive=1", cancellationToken);
        if (!response.IsSuccessStatusCode) return [];
        using var json = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));
        return json.RootElement.TryGetProperty("tree", out var tree) ? tree.EnumerateArray().Where(x => x.GetProperty("type").GetString() == "blob").Select(x => x.GetProperty("path").GetString()!).ToList() : [];
    }
}
