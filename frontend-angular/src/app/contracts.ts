export interface Release { id: number; projectId: number; releaseVersion: string; status: string; createdAt: string; }
export interface ScanFinding { id: number; scanType: string; severity: string; title?: string; description?: string; filePath?: string; lineNumber?: number; }
export interface FindingPage { page: number; pageSize: number; total: number; items: ScanFinding[]; }
export interface Decision { releaseId: number; riskScore: number; riskLevel: string; decision: string; reason: string; }
export interface RemediationRequest { scanner: string; findingId: string; severity: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'; fileLocation?: string; description: string; }
export interface Remediation { explanation: string; potentialImpact: string; suggestedRemediation: string; preventionMeasures: string[]; }
