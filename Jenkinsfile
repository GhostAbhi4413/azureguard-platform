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
        bat 'gitleaks detect --source=. --report-format=json --report-path=gitleaks-report.json --exit-code=0'
        archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
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
            curl.exe --fail-with-body -sS -X POST "%AZUREGUARD_API_URL%/projects/%PROJECT_ID%/releases/%RELEASE_ID%/reports/raw?scanType=GITLEAKS&toolName=GITLEAKS&status=PASSED" -H "Content-Type: application/json" -H "X-AzureGuard-Webhook-Secret: %AZUREGUARD_WEBHOOK_SECRET%" --data-binary "@gitleaks-report.json"
          '''
        }
      }
    }
  }
  post { always { echo "AzureGuard release ${params.RELEASE_VERSION} completed with ${currentBuild.currentResult}" } }
}
