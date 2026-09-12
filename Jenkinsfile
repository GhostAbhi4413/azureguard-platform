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
    stage('Security scan') { steps { echo 'Scanner installation and report publishing will be enabled after the Jenkins tools are configured.' } }
  }
  post { always { echo "AzureGuard release ${params.RELEASE_VERSION} completed with ${currentBuild.currentResult}" } }
}
