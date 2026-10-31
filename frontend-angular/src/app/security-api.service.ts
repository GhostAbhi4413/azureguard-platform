import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { FindingPage, Decision, Remediation, RemediationRequest } from './contracts';

@Injectable({ providedIn: 'root' })
export class SecurityApiService {
  private readonly http = inject(HttpClient);
  private readonly base = (globalThis as { AZUREGUARD_API_URL?: string }).AZUREGUARD_API_URL ?? 'http://localhost:5006/api';
  private headers(): HttpHeaders {
    const token = sessionStorage.getItem('azureguard_token');
    return token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : new HttpHeaders();
  }
  findings(releaseId: number) { return this.http.get<FindingPage>(`${this.base}/releases/${releaseId}/findings?page=1&pageSize=50`, { headers: this.headers() }); }
  decision(releaseId: number) { return this.http.post<Decision>(`${this.base}/releases/${releaseId}/risk-evaluation`, {}, { headers: this.headers() }); }
  remediation(request: RemediationRequest) { return this.http.post<Remediation>(`${this.base}/ai/remediation`, request, { headers: this.headers() }); }
}
