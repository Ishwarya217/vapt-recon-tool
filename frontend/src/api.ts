import axios from 'axios';

export const API_BASE_URL = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api/v1`
  : '/api/v1';

const api = axios.create({ baseURL: API_BASE_URL });

export interface ScanCreate {
  target_domain: string;
  scope?: string;
  sources?: string[];
  mode?: string;
}

export interface ScanStats {
  total_discoveries: number;
  total_assets: number;
  active_assets: number;
  dns_valid: number;
  tls_assessed: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
}

export interface Scan {
  id: string;
  target_domain: string;
  status: string;
  mode: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  theharvester_version?: string;
  testssl_version?: string;
  stats?: ScanStats;
}

export interface Discovery {
  id: string;
  scan_id: string;
  hostname: string;
  domain: string;
  source: string;
  source_engine?: string;
  record_type: string;
  ip_address?: string;
  discovered_at: string;
}

export interface Asset {
  id: string;
  scan_id: string;
  hostname: string;
  source?: string;
  status: string;
  dns_resolved: boolean;
  ip_addresses: string[];
  cname?: string;
  dns_resolution_time_ms?: number;
  http_status_code?: number;
  https_status_code?: number;
  http_response_time_ms?: number;
  https_response_time_ms?: number;
  server_header?: string;
  has_hsts?: boolean;
  has_csp?: boolean;
  has_xfo?: boolean;
  has_xcto?: boolean;
  security_headers_score?: number;
  tls_assessed: boolean;
  tls_grade?: string;
  tls_results?: any[];
  cert_results?: any[];
  cipher_results?: any[];
  header_results?: any[];
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  asset_hostname?: string;
  category?: string;
  severity: string;
  title: string;
  description?: string;
  evidence?: string;
  recommendation?: string;
  cve?: string;
  cwe?: string;
  created_at: string;
}

export interface ToolStatus { name: string; available: boolean; version?: string; error?: string; }
export interface SystemHealth { status: string; scanner_mode: string; tools: ToolStatus[]; database: string; timestamp: string; }

export interface DashboardStats {
  total_scans: number;
  completed_scans: number;
  active_assets: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  scanner_mode: string;
}

// API calls
export const getHealth = () => api.get<SystemHealth>('/system/health').then(r => r.data);
export const getDashboard = () => api.get<DashboardStats>('/dashboard/stats').then(r => r.data);
export const getScans = () => api.get<Scan[]>('/scans').then(r => r.data);
export const getScan = (id: string) => api.get<Scan>(`/scans/${id}`).then(r => r.data);
export const createScan = (body: ScanCreate) => api.post<Scan>('/scans', body).then(r => r.data);
export const deleteScan = (id: string) => api.delete(`/scans/${id}`);
export const getDiscoveries = (id: string) => api.get<Discovery[]>(`/scans/${id}/discoveries`).then(r => r.data);
export const getAssets = (id: string) => api.get<Asset[]>(`/scans/${id}/assets`).then(r => r.data);
export const getFindings = (id: string, sev?: string) => api.get<Finding[]>(`/scans/${id}/findings`, { params: sev ? { severity: sev } : {} }).then(r => r.data);
export const downloadReport = (id: string, format: 'pdf' | 'excel' | 'json' | 'xml') =>
  api.post(`/scans/${id}/reports/${format}`, {}, { responseType: 'blob' }).then(r => r.data);

