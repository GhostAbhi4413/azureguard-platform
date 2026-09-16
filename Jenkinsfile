pipeline {
  agent any
  options { skipDefaultCheckout(true) }
  parameters {
    string(name: 'PROJECT_ID')
    string(name: 'RELEASE_ID')
    string(name: 'REPOSITORY_URL')
    string(name: 'BRANCH_NAME', defaultValue: 'main')
    string(name: 'RELEASE_VERSION')
  }
  stages {
    // The Pipeline-from-SCM job already checks out this repository. Reusing scm
    // avoids a second checkout with an empty REPOSITORY_URL parameter.
    stage('Checkout') { steps { checkout scm } }
    stage('Build') { steps { bat '''
      if exist backend/AzureGuard/AzureGuard.sln (
        dotnet restore backend/AzureGuard/AzureGuard.sln --configfile backend/NuGet.Config
        if errorlevel 1 exit /b 1
        dotnet build backend/AzureGuard/AzureGuard.sln --configuration Release --no-restore
        if errorlevel 1 exit /b 1
      )
      if exist frontend/package.json (
        cd frontend
        call npm ci
        if errorlevel 1 exit /b 1
        call npm run build
        if errorlevel 1 exit /b 1
      )
    ''' } }
    stage('Test') { steps { bat '''
      if exist backend/AzureGuard/AzureGuard.sln dotnet test backend/AzureGuard/AzureGuard.sln --configuration Release --no-restore --no-build
      if exist frontend/package.json echo Frontend tests will run when the test suite is added
    ''' } }
    stage('Security scan') {
      steps {
        bat 'gitleaks version'
        bat 'gitleaks detect --no-git --source=. --report-format=json --report-path=gitleaks-report.json --exit-code=0'
        archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
        bat 'docker --version'
        bat 'docker run --rm -v "%CD%:/src" aquasec/trivy:latest fs --format json --output /src/trivy-report.json /src'
        archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
        withCredentials([string(credentialsId: 'azureguard-webhook-secret', variable: 'AZUREGUARD_WEBHOOK_SECRET')]) {
          bat '''
            if not defined PROJECT_ID (
              echo No AzureGuard release context supplied; skipping report upload for SCM validation build.
              exit /b 0
            )
            if not defined RELEASE_ID (
              echo No AzureGuard release context supplied; skipping report upload for SCM validation build.
              exit /b 0
            )
            if not defined AZUREGUARD_API_URL set AZUREGUARD_API_URL=http://localhost:5006/api
            for /f "delims=" %%S in ('powershell -NoProfile -Command "$secret=$env:AZUREGUARD_WEBHOOK_SECRET; $body=[IO.File]::ReadAllBytes('gitleaks-report.json'); $h=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($secret)); 'sha256=' + [Convert]::ToHexString($h.ComputeHash($body)).ToLowerInvariant()"') do set "GITLEAKS_SIGNATURE=%%S"
            curl.exe --fail-with-body -sS -X POST "%AZUREGUARD_API_URL%/projects/%PROJECT_ID%/releases/%RELEASE_ID%/reports/raw?scanType=GITLEAKS&toolName=GITLEAKS&status=PASSED" -H "Content-Type: application/json" -H "X-AzureGuard-Signature: %GITLEAKS_SIGNATURE%" --data-binary "@gitleaks-report.json"
            for /f "delims=" %%S in ('powershell -NoProfile -Command "$secret=$env:AZUREGUARD_WEBHOOK_SECRET; $body=[IO.File]::ReadAllBytes('trivy-report.json'); $h=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($secret)); 'sha256=' + [Convert]::ToHexString($h.ComputeHash($body)).ToLowerInvariant()"') do set "TRIVY_SIGNATURE=%%S"
            curl.exe --fail-with-body -sS -X POST "%AZUREGUARD_API_URL%/projects/%PROJECT_ID%/releases/%RELEASE_ID%/reports/raw?scanType=SCA&toolName=TRIVY&status=PASSED" -H "Content-Type: application/json" -H "X-AzureGuard-Signature: %TRIVY_SIGNATURE%" --data-binary "@trivy-report.json"
          '''
        }
      }
    }
  }
  post { always { echo "AzureGuard release ${params.RELEASE_VERSION} completed with ${currentBuild.currentResult}" } }
}
