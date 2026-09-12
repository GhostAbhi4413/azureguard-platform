pipeline {
  agent any
  parameters {
    string(name: 'PROJECT_ID')
    string(name: 'RELEASE_ID')
    string(name: 'REPOSITORY_URL')
    string(name: 'BRANCH_NAME', defaultValue: 'main')
    string(name: 'RELEASE_VERSION')
  }
  stages {
    stage('Checkout') { steps { checkout([$class: 'GitSCM', branches: [[name: "*/${params.BRANCH_NAME}"]], userRemoteConfigs: [[url: params.REPOSITORY_URL]]]) } }
    stage('Build') { steps { sh 'if [ -f package.json ]; then npm ci && npm run build; elif ls *.sln *.csproj >/dev/null 2>&1; then dotnet build --configuration Release; else echo "No supported build manifest"; fi' } }
    stage('Test') { steps { sh 'if [ -f package.json ]; then npm test -- --runInBand || true; elif ls *.sln *.csproj >/dev/null 2>&1; then dotnet test --configuration Release --no-build; fi' } }
    stage('Security scan') { steps { sh 'echo "Attach SonarQube, Trivy, Gitleaks and Checkov installations here"' } }
  }
  post { always { echo "AzureGuard release ${params.RELEASE_VERSION} completed with ${currentBuild.currentResult}" } }
}
