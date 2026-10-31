export interface Release { id: number; projectId: number; releaseVersion: string; branchName: string; commitSha?: string | null; status: string; createdAt: string; }
export interface Project { id: number; name: string; description?: string | null; repositoryUrl: string; branchName: string; techStack?: string; createdAt: string; }
export interface ScanFinding { id: number; scanType: string; severity: string; title?: string; description?: string; filePath?: string; lineNumber?: number; }
export interface FindingPage { page: number; pageSize: number; total: number; items: ScanFinding[]; }
export interface Decision { releaseId: number; riskScore: number; riskLevel: string; decision: string; reason: string; }
export interface RemediationRequest { scanner: string; findingId: string; severity: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'; fileLocation?: string; description: string; }
export interface Remediation { explanation: string; potentialImpact: string; suggestedRemediation: string; preventionMeasures: string[]; }
export interface ChangeEvidence { filePath: string; changeSummary: string; rationale: string; }
export interface ChangeImpactAnalysis { releaseId: number; commitReference: string | null; status: 'AVAILABLE' | 'UNAVAILABLE' | 'SKIPPED'; potentialRisk: string | null; explanation: string | null; evidence: ChangeEvidence[]; remediation: string | null; recommendedTests: string[]; manualReviewRecommended: boolean | null; modelId: string | null; deploymentName: string | null; failureReason: string | null; createdAt: string; }
export interface AuthResponse { userId: number; fullName: string; email: string; roleName: string; token: string; }
export interface CreateProjectRequest { name: string; description: string | null; repositoryUrl: string; branchName: string; }
export interface CreateReleaseRequest { releaseVersion: string; branchName: string; commitSha: string | null; }
