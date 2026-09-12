param([switch]$StartJenkins)

$ErrorActionPreference = 'Stop'

Write-Host 'AzureGuard personal-laptop setup' -ForegroundColor Cyan

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw 'Windows Package Manager (winget) is not available. Install Microsoft App Installer from the Microsoft Store, then run this script again.'
}

$packages = @(
    @{ Id = 'Git.Git'; Name = 'Git' },
    @{ Id = 'Microsoft.DotNet.SDK.8'; Name = '.NET 8 SDK' },
    @{ Id = 'OpenJS.NodeJS.LTS'; Name = 'Node.js LTS' },
    @{ Id = 'Python.Python.3.12'; Name = 'Python 3.12' },
    @{ Id = 'Microsoft.OpenJDK.21'; Name = 'OpenJDK 21' },
    @{ Id = 'Docker.DockerDesktop'; Name = 'Docker Desktop' }
)

foreach ($package in $packages) {
    Write-Host "Installing $($package.Name)..." -ForegroundColor Yellow
    winget install --id $package.Id --exact --accept-source-agreements --accept-package-agreements
}

Write-Host 'Checking installed tools...' -ForegroundColor Cyan
git --version
dotnet --version
node --version
python --version
docker --version

Write-Host ''
Write-Host 'Docker Desktop may require a restart and must be started before Jenkins can run.' -ForegroundColor Yellow
Write-Host 'After Docker Desktop is running, execute this script again with -StartJenkins.' -ForegroundColor Yellow

if ($StartJenkins) {
    if (-not (docker info 2>$null)) {
        throw 'Docker is not running. Start Docker Desktop and run this script again with -StartJenkins.'
    }

    $existing = docker ps -aq --filter 'name=^azureguard-jenkins$'
    if ($existing) {
        docker start azureguard-jenkins | Out-Null
    } else {
        docker volume create jenkins_home | Out-Null
        docker run -d `
            --name azureguard-jenkins `
            --restart unless-stopped `
            -p 8080:8080 `
            -p 50000:50000 `
            -v jenkins_home:/var/jenkins_home `
            jenkins/jenkins:lts-jdk21 | Out-Null
    }

    Write-Host 'Jenkins started at http://localhost:8080' -ForegroundColor Green
    Write-Host 'Initial Jenkins password:' -ForegroundColor Green
    docker exec azureguard-jenkins cat /var/jenkins_home/secrets/initialAdminPassword
}
