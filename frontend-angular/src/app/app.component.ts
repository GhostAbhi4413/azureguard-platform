import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from './security-api.service';
import { Decision, FindingPage, Remediation } from './contracts';

@Component({ selector: 'ag-root', standalone: true, imports: [FormsModule], template: `
  <main>
  @if (!authenticated()) { <section class="card auth"><p class="eyebrow">RELEASE SECURITY</p><h1>AzureGuard</h1><p>Sign in to review release risk and findings.</p><label for="email">Email</label><input id="email" type="email" [(ngModel)]="email"/><label for="password">Password</label><input id="password" type="password" [(ngModel)]="password"/><button (click)="login()" [disabled]="loading()">{{ loading() ? 'Signing in…' : 'Sign in' }}</button>@if (error()) { <p class="error" role="alert">{{ error() }}</p> }</section> }
  @else { <header><div><p class="eyebrow">RELEASE SECURITY</p><h1>AzureGuard</h1></div><div><span>Risk review dashboard</span><button class="secondary" (click)="logout()">Sign out</button></div></header>
  <section class="card"><label for="release">Release ID</label><div class="row"><input id="release" type="number" min="1" [(ngModel)]="releaseId"/><button (click)="load()" [disabled]="loading()">{{ loading() ? 'Loading…' : 'Load release' }}</button></div>
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
  </section>
  @if (decision(); as d) { <section class="card"><p class="eyebrow">RELEASE DECISION</p><h2>{{ d.decision }} · {{ d.riskLevel }} risk</h2><p>Score {{ d.riskScore }}</p><p>{{ d.reason }}</p></section> }
  @if (findings(); as f) { <section class="card"><h2>Security findings <small>{{ f.total }}</small></h2>@if (f.items.length === 0) { <p>No findings reported for this release.</p> } @for (item of f.items; track item.id) { <article><b>{{ item.severity }}</b> · {{ item.title || item.scanType }}<p>{{ item.description }}</p><small>{{ item.filePath }}{{ item.lineNumber ? ':' + item.lineNumber : '' }}</small><button class="secondary" (click)="explain(item)">Explain remediation</button></article> }</section> }
  @if (remediation(); as r) { <section class="card"><h2>AI remediation guidance</h2><p>{{ r.explanation }}</p><p><b>Impact:</b> {{ r.potentialImpact }}</p><p><b>Fix:</b> {{ r.suggestedRemediation }}</p><p><b>Prevention:</b> {{ r.preventionMeasures.join(', ') }}</p><small>AI guidance is advisory; release policy remains deterministic.</small></section> }
  }
  </main>`, styles: [`:host{font:16px system-ui;color:#e9eef7;background:#0b1220;display:block;min-height:100vh}main{max-width:850px;margin:auto;padding:32px 20px}header,.row{display:flex;justify-content:space-between;align-items:center}.eyebrow{color:#70d6c4;letter-spacing:.12em;font-size:.75rem}h1{margin:0;font-size:2.2rem}h2{font-size:1.25rem}small{color:#a9b7ca}.card{background:#141e30;border:1px solid #27364d;border-radius:14px;padding:20px;margin:18px 0}.auth{max-width:460px;margin:12vh auto;display:grid;gap:12px}input{background:#0b1220;color:white;border:1px solid #50617a;border-radius:8px;padding:10px}button{background:#70d6c4;color:#09211e;border:0;border-radius:8px;padding:10px 14px;cursor:pointer}.secondary{margin-left:12px}.error{color:#ff8c8c}article{border-top:1px solid #27364d;padding:14px 0}`] })
export class AppComponent {
  private readonly api = inject(SecurityApiService);
  releaseId = 1;
  email = '';
  password = '';
  readonly authenticated = signal(!!sessionStorage.getItem('azureguard_token'));
  readonly loading = signal(false);
  readonly error = signal('');
  readonly findings = signal<FindingPage | null>(null);
  readonly decision = signal<Decision | null>(null);
  readonly remediation = signal<Remediation | null>(null);
  login() {
    this.loading.set(true); this.error.set('');
    this.api.login(this.email, this.password).subscribe({ next: result => { sessionStorage.setItem('azureguard_token', result.token); this.authenticated.set(true); this.loading.set(false); }, error: e => { this.error.set(e.message || 'Sign-in failed.'); this.loading.set(false); } });
  }
  logout() { sessionStorage.removeItem('azureguard_token'); this.authenticated.set(false); this.findings.set(null); this.decision.set(null); }
  load() {
    this.loading.set(true); this.error.set(''); this.remediation.set(null);
    this.api.findings(this.releaseId).subscribe({ next: x => this.findings.set(x), error: e => this.error.set(e.message || 'Unable to load findings.') });
    this.api.decision(this.releaseId).subscribe({ next: x => { this.decision.set(x); this.loading.set(false); }, error: e => { this.error.set(e.message || 'Unable to load release decision.'); this.loading.set(false); } });
  }
  explain(finding: FindingPage['items'][number]) {
    this.error.set('');
    this.api.remediation({ scanner: finding.scanType, findingId: String(finding.id), severity: finding.severity as 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO', fileLocation: finding.filePath, description: finding.description || finding.title || 'Security finding' }).subscribe({ next: x => this.remediation.set(x), error: e => this.error.set(e.message || 'AI remediation is unavailable.') });
  }
}
