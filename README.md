# AzureGuard Platform

AzureGuard is an automated DevSecOps platform, code security scanner, and CI/CD quality gate designed to intercept exposed API tokens, cloud credentials, and sensitive secrets before code reaches production.

---

## Overview

Modern applications frequently integrate third-party APIs, cloud providers, and LLM services. AzureGuard acts as an automated pipeline gate that analyzes pull requests, repository commits, and application payloads to detect leaked keys and credentials with minimal false positives.

It supports automated multi-agent CI/CD environments (GitHub Actions, Jenkins) and produces verifiable, tamper-evident audit logs to safeguard enterprise software supply chains.

---

## Key Features

- **Automated Secret & Token Scanning:** Scans codebases using high-entropy analysis and regex parsing to identify exposed keys (OpenAI, Google Gemini, Azure, AWS, and generic authorization tokens).
- **CI/CD Quality & Security Gate:** Blocks pull requests failing compliance thresholds in automated build pipelines.
- **HMAC Report Verification:** Secures scan reports and audit logs with HMAC signatures to guarantee integrity between runners and central dashboards.
- **Structured Audit Logging:** Exports detailed JSON compliance logs with file paths, line numbers, entropy scores, and remediation steps.
- **Lightweight & Containerized:** Distributed as optimized Docker containers ready for Linux and Windows build agents.

---

## Tech Stack

- **Core & Scanner:** Python, Regex & Shannon Entropy Algorithms
- **CI/CD & Runners:** GitHub Actions, Jenkins (`Jenkinsfile`)
- **Containerization:** Docker
- **Frontend / Dashboard:** Modern Web Interface (React / HTML / Tailwind)
- **Security:** HMAC-SHA256 Report Signing, Role-Based Access

---

## Project Structure

```text
azureguard-platform/
├── .github/workflows/      # Automated CI/CD scanning workflows
├── backend/                # Scanner engine, API server, and HMAC verification
├── frontend/               # Web dashboard for scan monitoring and audit trails
├── tools/                  # Verification scripts and helper utilities
├── Jenkinsfile             # Declarative pipeline script for Jenkins runners
├── PROJECT_STATUS.md       # Development progress and milestones
└── README.md               # Project documentation
