export type ScanStatus = "pending" | "running" | "completed" | "failed";

export interface Scan {
  id: string;
  user_id: number;
  target: string;
  status: ScanStatus;
  risk_level: string;
  finding_count: number;
  high_count: number;
  critical_count: number;
  report_markdown?: string;
  report_json?: string;
  report_html?: string;
  document_json?: string;
  error_message?: string;
  created_at: string;
  finished_at?: string;
}

export interface Schedule {
  id: string;
  user_id: number;
  target: string;
  interval_minutes: number;
  enabled: boolean;
  last_run_at?: string;
  created_at: string;
}

export interface ScanDocument {
  summary: {
    target: string;
    generated_at: string;
    modules_run: number;
    finding_count: number;
  };
  stack?: string[];
  infrastructure?: string[];
  header_checks?: HeaderCheck[];
  bundle?: BundleResult;
  endpoints?: EndpointProbe[];
  auth?: AuthResult;
  plugins?: PluginCollection;
  nuclei?: NucleiResult;
  burp?: BurpResult;
  ai?: AIResult;
  recon_assets?: ReconAsset[];
  findings?: Finding[];
  risk: { level: string; score: number; counts: Record<string, number> };
  recommendations?: string[];
  fingerprint?: FingerprintResult;
}

export interface HeaderCheck {
  name: string;
  present: boolean;
  value?: string;
  ok?: boolean;
  detail?: string;
}

export interface BundleResult {
  scripts?: { url: string; source: string }[];
  libraries?: { name: string; version?: string }[];
  routes?: string[];
  secrets?: { file: string; line: number; pattern: string }[];
}

export interface EndpointProbe {
  path: string;
  status: number;
  method: string;
  redirect?: string;
}

export interface AuthResult {
  login_paths?: string[];
  logout_paths?: string[];
  refresh_paths?: string[];
  jwt_detected?: boolean;
  csrf_detected?: boolean;
  session_cookies?: string[];
}

export interface PluginCollection {
  httpx?: { target: string; status_code: number; title?: string }[];
  nmap?: { port: number; protocol: string; state: string }[];
  nuclei?: { template: string; severity: string; url: string }[];
}

export interface NucleiResult {
  findings?: { template: string; severity: string; url: string; matched: string }[];
  total?: number;
}

export interface BurpResult {
  issues?: { name: string; severity: string; url: string; detail: string }[];
}

export interface PriorityItem {
  rank: number;
  title: string;
  severity: string;
  score: number;
  rationale: string;
}

export interface AIResult {
  executive_summary?: string;
  summary?: string;
  hypotheses?: string[];
  attack_surface?: string[];
  prioritization?: PriorityItem[];
  recommendations?: string[];
}

export interface ReconAsset {
  path: string;
  status: number;
  summary?: string;
}

export interface Finding {
  id: string;
  module: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  cwe?: string;
  evidence?: string;
  recommendation?: string;
  layperson_impact?: string;
  layperson_recommendation?: string;
  owasp?: string;
  asvs?: string;
  capec?: string;
  cvss?: string;
}

export interface FingerprintResult {
  server?: string;
  tls_version?: string;
  tls_cipher?: string;
  cookies?: { name: string; secure: boolean; httpOnly: boolean; sameSite: string }[];
  frameworks?: { name: string; version?: string }[];
  infra?: string[];
}
