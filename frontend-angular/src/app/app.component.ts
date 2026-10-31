import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from './security-api.service';
import { ChangeImpactAnalysis, Decision, FindingPage, Project, Release, Remediation } from './contracts';

@Component({ selector: 'ag-root', standalone: true, imports: [FormsModule], template: `
  <main>
  @if (!authenticated()) {
    <section class="card auth">
      <p class="eyebrow">RELEASE SECURITY</p><h1>AzureGuard</h1>
      <p>{{ signupMode() ? 'Create an account to manage projects and releases.' : 'Sign in to review release risk and findings.' }}</p>
      @if (signupMode()) { <label for="fullName">Full name</label><input id="fullName" [(ngModel)]="fullName" autocomplete="name"/> }
      <label for="email">Email</label><input id="email" type="email" [(ngModel)]="email" autocomplete="email"/>
      <label for="password">Password</label><input id="password" type="password" [(ngModel)]="password" autocomplete="current-password"/>
      @if (signupMode()) { <small>Use at least 8 characters.</small> }
      <button (click)="submitAuth()" [disabled]="loading()">{{ loading() ? 'Please wait…' : signupMode() ? 'Create account' : 'Sign in' }}</button>
      <button class="link" (click)="toggleAuth()" [disabled]="loading()">{{ signupMode() ? 'Already registered? Sign in' : 'New to AzureGuard? Create an account' }}</button>
      @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
    </section>
  } @else {
    <header><div><p class="eyebrow">RELEASE SECURITY</p><h1>AzureGuard</h1></div><div><span>Project and release review</span><button class="secondary" (click)="logout()">Sign out</button></div></header>
    @if (error()) { <p class="error card" role="alert">{{ error() }}</p> }
    <section class="card">
      <div class="section-heading"><div><p class="eyebrow">PROJECTS</p><h2>Projects</h2></div><button class="secondary" (click)="refreshProjects()" [disabled]="loading()">Refresh</button></div>
      @if (projects().length === 0) { <p>No projects are available in this account yet. Add a public GitHub repository to get started.</p> }
      <div class="row"><label for="project">Select project</label><select id="project" [ngModel]="selectedProjectId()" (ngModelChange)="selectProject($event)"><option [ngValue]="null">Choose a project</option>@for (project of projects(); track project.id) { <option [ngValue]="project.id">{{ project.name }} · {{ project.repositoryUrl }}</option> }</select></div>
      <details><summary>Add project</summary><div class="form-grid"><label>Name<input [(ngModel)]="projectName"/></label><label>Repository URL<input type="url" placeholder="https://github.com/org/repository" [(ngModel)]="repositoryUrl"/></label><label>Branch<input [(ngModel)]="projectBranch"/></label><label>Description<input [(ngModel)]="projectDescription"/></label></div><button (click)="createProject()" [disabled]="loading()">{{ loading() ? 'Saving…' : 'Create project' }}</button></details>
    </section>
    @if (selectedProject(); as project) {
      <section class="card">
        <div class="section-heading"><div><p class="eyebrow">RELEASES · {{ project.name }}</p><h2>Releases</h2></div><button class="secondary" (click)="refreshReleases()" [disabled]="loading()">Refresh</button></div>
        <div class="row"><label for="release">Select release</label><select id="release" [ngModel]="selectedReleaseId()" (ngModelChange)="selectRelease($event)"><option [ngValue]="null">Choose a release</option>@for (release of releases(); track release.id) { <option [ngValue]="release.id">{{ release.releaseVersion }} · {{ release.status }}</option> }</select><button (click)="loadRelease()" [disabled]="!selectedReleaseId() || loading()">Review</button></div>
        <details><summary>Create release</summary><div class="form-grid"><label>Release version<input placeholder="v1.0.0" [(ngModel)]="releaseVersion"/></label><label>Branch<input [(ngModel)]="releaseBranch"/></label><label>Commit SHA (optional)<input [(ngModel)]="commitSha"/></label></div><button (click)="createRelease()" [disabled]="loading()">{{ loading() ? 'Creating…' : 'Create release' }}</button></details>
      </section>
    }
    @if (selectedRelease(); as release) { <section class="card"><p class="eyebrow">SELECTED RELEASE</p><h2>{{ release.releaseVersion }} <small>· {{ release.status }}</small></h2><p>Release ID {{ release.id }} · Branch {{ release.branchName }}</p></section> }
    @if (decision(); as d) { <section class="card"><p class="eyebrow">DETERMINISTIC RELEASE DECISION</p><h2>{{ d.decision }} · {{ d.riskLevel }} risk</h2><p>Score {{ d.riskScore }}</p><p>{{ d.reason }}</p></section> }
    @if (changeImpact(); as impact) { <section class="card"><p class="eyebrow">AI SECURITY CHANGE IMPACT · ADVISORY</p>@if (impact.status === 'AVAILABLE') { <h2>{{ impact.potentialRisk }} potential risk</h2><p>{{ impact.explanation }}</p><h3>Evidence</h3>@for (item of impact.evidence; track $index) { <article><b>{{ item.filePath }}</b><p>{{ item.changeSummary }}</p><small>{{ item.rationale }}</small></article> }<p><b>Recommended remediation:</b> {{ impact.remediation }}</p><p><b>Recommended tests:</b> {{ impact.recommendedTests.join(', ') }}</p><p><b>Manual review recommended:</b> {{ impact.manualReviewRecommended ? 'Yes' : 'No' }}</p><small>Model {{ impact.modelId }} · deployment {{ impact.deploymentName }} · commit {{ impact.commitReference }}</small> } @else { <h2>{{ impact.status === 'SKIPPED' ? 'No in-scope changes' : 'Analysis unavailable' }}</h2><p>{{ impact.failureReason }}</p> }<p class="notice">This AI assessment does not change the deterministic release decision.</p></section> }
    @if (findings(); as f) { <section class="card"><h2>Security findings <small>{{ f.total }}</small></h2>@if (f.items.length === 0) { <p>No findings reported for this release.</p> } @for (item of f.items; track item.id) { <article><b>{{ item.severity }}</b> · {{ item.title || item.scanType }}<p>{{ item.description }}</p><small>{{ item.filePath }}{{ item.lineNumber ? ':' + item.lineNumber : '' }}</small><button class="secondary" (click)="explain(item)">Explain remediation</button></article> }</section> }
    @if (remediation(); as r) { <section class="card"><h2>AI remediation guidance</h2><p>{{ r.explanation }}</p><p><b>Impact:</b> {{ r.potentialImpact }}</p><p><b>Fix:</b> {{ r.suggestedRemediation }}</p><p><b>Prevention:</b> {{ r.preventionMeasures.join(', ') }}</p><small>AI guidance is advisory; release policy remains deterministic.</small></section> }
  }
</main>`, styles: [`:host{font:16px system-ui;color:#e9eef7;background:#0b1220;display:block;min-height:100vh}main{max-width:1000px;margin:auto;padding:32px 20px}header,.row,.section-heading{display:flex;justify-content:space-between;align-items:center;gap:12px}.eyebrow{color:#70d6c4;letter-spacing:.12em;font-size:.75rem}h1{margin:0;font-size:2.2rem}h2{font-size:1.25rem;margin:.25rem 0}.card{background:#141e30;border:1px solid #27364d;border-radius:14px;padding:20px;margin:18px 0}.auth{max-width:460px;margin:12vh auto;display:grid;gap:12px}input,select{background:#0b1220;color:white;border:1px solid #50617a;border-radius:8px;padding:10px;min-width:180px}select{flex:1}button{background:#70d6c4;color:#09211e;border:0;border-radius:8px;padding:10px 14px;cursor:pointer}.secondary,.link{background:transparent;color:#70d6c4;border:1px solid #50617a}.link{border:0}.error{color:#ff8c8c}article{border-top:1px solid #27364d;padding:14px 0}details{border-top:1px solid #27364d;margin-top:18px;padding-top:14px}summary{cursor:pointer;color:#70d6c4;margin-bottom:14px}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:14px}.form-grid label{display:grid;gap:6px}small{color:#a9b7ca}@media(max-width:650px){header,.row{align-items:stretch;flex-direction:column}.row button{width:100%}}`] })
export class AppComponent {
  private readonly api = inject(SecurityApiService);
  readonly authenticated = signal(!!sessionStorage.getItem('azureguard_token'));
  readonly signupMode = signal(false);
  readonly loading = signal(false);
  readonly error = signal('');
  readonly projects = signal<Project[]>([]);
  readonly releases = signal<Release[]>([]);
  readonly selectedProjectId = signal<number | null>(null);
  readonly selectedReleaseId = signal<number | null>(null);
  readonly findings = signal<FindingPage | null>(null);
  readonly decision = signal<Decision | null>(null);
  readonly remediation = signal<Remediation | null>(null);
  readonly changeImpact = signal<ChangeImpactAnalysis | null>(null);
  email = ''; password = ''; fullName = '';
  projectName = ''; repositoryUrl = ''; projectBranch = 'main'; projectDescription = '';
  releaseVersion = ''; releaseBranch = 'main'; commitSha = '';
  selectedProject() { return this.projects().find(x => x.id === this.selectedProjectId()) ?? null; }
  selectedRelease() { return this.releases().find(x => x.id === this.selectedReleaseId()) ?? null; }

  constructor() { if (this.authenticated()) this.refreshProjects(); }
  toggleAuth() { this.signupMode.update(x => !x); this.error.set(''); }
  submitAuth() {
    this.error.set(''); this.loading.set(true);
    const request = this.signupMode() ? this.api.signup(this.fullName, this.email, this.password) : this.api.login(this.email, this.password);
    request.subscribe({ next: result => { sessionStorage.setItem('azureguard_token', result.token); this.authenticated.set(true); this.loading.set(false); this.refreshProjects(); }, error: e => this.fail(e, this.signupMode() ? 'Account creation failed.' : 'Sign-in failed.') });
  }
  logout() { sessionStorage.removeItem('azureguard_token'); this.authenticated.set(false); this.projects.set([]); this.releases.set([]); this.clearReview(); }
  refreshProjects() { this.api.projects().subscribe({ next: items => this.projects.set(items), error: e => this.setError(e, 'Unable to load projects.') }); }
  selectProject(id: number | null) { this.selectedProjectId.set(id); this.selectedReleaseId.set(null); this.releases.set([]); this.clearReview(); if (id) this.refreshReleases(); }
  refreshReleases() { const id = this.selectedProjectId(); if (!id) return; this.api.releases(id).subscribe({ next: items => this.releases.set(items), error: e => this.setError(e, 'Unable to load releases.') }); }
  selectRelease(id: number | null) { this.selectedReleaseId.set(id); this.clearReview(); }
  createProject() {
    this.begin(); this.api.createProject({ name: this.projectName, description: this.projectDescription || null, repositoryUrl: this.repositoryUrl, branchName: this.projectBranch || 'main' }).subscribe({ next: project => { this.projects.update(items => [project, ...items]); this.projectName = ''; this.projectDescription = ''; this.repositoryUrl = ''; this.selectProject(project.id); this.loading.set(false); }, error: e => this.fail(e, 'Project creation failed. Check the GitHub URL and API connection.') });
  }
  createRelease() {
    const projectId = this.selectedProjectId(); if (!projectId) return;
    this.begin(); this.api.createRelease(projectId, { releaseVersion: this.releaseVersion, branchName: this.releaseBranch || 'main', commitSha: this.commitSha || null }).subscribe({ next: release => { this.releases.update(items => [release, ...items]); this.selectedReleaseId.set(release.id); this.releaseVersion = ''; this.commitSha = ''; this.loading.set(false); this.clearReview(); }, error: e => this.fail(e, 'Release creation failed.') });
  }
  loadRelease() {
    const id = this.selectedReleaseId(); const projectId = this.selectedProjectId(); if (!id || !projectId) return;
    this.begin(); this.remediation.set(null);
    this.api.findings(id).subscribe({ next: x => this.findings.set(x), error: e => this.setError(e, 'Unable to load findings.') });
    this.api.decision(id).subscribe({ next: x => { this.decision.set(x); this.loading.set(false); }, error: e => this.fail(e, 'Unable to load release decision.') });
    this.api.changeImpact(projectId, id).subscribe({ next: x => this.changeImpact.set(x), error: e => this.setError(e, 'Unable to load change-impact analysis.') });
  }
  explain(finding: FindingPage['items'][number]) {
    this.error.set('');
    this.api.remediation({ scanner: finding.scanType, findingId: String(finding.id), severity: finding.severity as 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO', fileLocation: finding.filePath, description: finding.description || finding.title || 'Security finding' }).subscribe({ next: x => this.remediation.set(x), error: e => this.setError(e, 'AI remediation is unavailable.') });
  }
  private clearReview() { this.findings.set(null); this.decision.set(null); this.remediation.set(null); this.changeImpact.set(null); }
  private begin() { this.loading.set(true); this.error.set(''); }
  private fail(error: unknown, fallback: string) { this.setError(error, fallback); this.loading.set(false); }
  private setError(error: any, fallback: string) { this.error.set(error?.error?.detail || error?.error?.message || error?.error || error?.message || fallback); }
}
