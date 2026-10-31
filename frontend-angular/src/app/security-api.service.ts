import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { AuthResponse, FindingPage, Decision, Project, Release, Remediation, RemediationRequest, CreateProjectRequest, CreateReleaseRequest, ChangeImpactAnalysis } from './contracts';

@Injectable({ providedIn: 'root' })
export class SecurityApiService {
  private readonly http = inject(HttpClient);
  private readonly base = (globalThis as { AZUREGUARD_API_URL?: string }).AZUREGUARD_API_URL ?? 'http://localhost:5006/api';
  private headers(): HttpHeaders {
    const token = sessionStorage.getItem('azureguard_token');
    return token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : new HttpHeaders();
  }
  login(email: string, password: string) { return this.http.post<AuthResponse>(`${this.base}/auth/login`, { email, password }); }
  signup(fullName: string, email: string, password: string) { return this.http.post<AuthResponse>(`${this.base}/auth/signup`, { fullName, email, password, roleName: 'Developer' }); }
  projects() { return this.http.get<Project[]>(`${this.base}/projects`, { headers: this.headers() }); }
  createProject(request: CreateProjectRequest) { return this.http.post<Project>(`${this.base}/projects`, request, { headers: this.headers() }); }
  releases(projectId: number) { return this.http.get<Release[]>(`${this.base}/projects/${projectId}/releases`, { headers: this.headers() }); }
  createRelease(projectId: number, request: CreateReleaseRequest) { return this.http.post<Release>(`${this.base}/projects/${projectId}/releases`, request, { headers: this.headers() }); }
  findings(releaseId: number) { return this.http.get<FindingPage>(`${this.base}/releases/${releaseId}/findings?page=1&pageSize=50`, { headers: this.headers() }); }
  decision(releaseId: number) { return this.http.post<Decision>(`${this.base}/releases/${releaseId}/risk-evaluation`, {}, { headers: this.headers() }); }
  remediation(request: RemediationRequest) { return this.http.post<Remediation>(`${this.base}/ai/remediation`, request, { headers: this.headers() }); }
  changeImpact(projectId: number, releaseId: number) { return this.http.get<ChangeImpactAnalysis | null>(`${this.base}/projects/${projectId}/releases/${releaseId}/change-impact`, { headers: this.headers() }); }
}
