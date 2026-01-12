export interface Subscription {
  id: string;
  display_name: string;
  tenant_id: string;
  state: string;
}

export interface SecurityFinding {
  id: string;
  resource_id: string;
  resource_name: string;
  resource_type: string;
  subscription_id: string;
  resource_group: string;
  location: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  recommendation: string;
  risk_score: number;
  metadata: Record<string, any>;
  timestamp: string;
}

export interface ScanResult {
  subscription_id: string;
  subscription_name?: string;
  scan_timestamp: string;
  total_resources_scanned: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  findings: SecurityFinding[];
  risk_score: number;
  scan_duration_seconds?: number;
}

export interface ScanRequest {
  subscription_id?: string;
  resource_types?: string[];
  severity_threshold?: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface ScanStatus {
  scan_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  started_at: string;
  completed_at?: string;
  error_message?: string;
}

export interface ScanStartResponse {
  scan_id: string;
  status: string;
  message: string;
}

export interface Report {
  filename: string;
  filepath: string;
  size: number;
  created: string;
  type: string;
}

export interface ReportStatistics {
  total_reports: number;
  total_size: number;
  total_size_mb: number;
  report_types: Record<string, number>;
  latest_report?: Report;
  oldest_report?: Report;
}

export interface RiskSummary {
  overall_risk_score: number;
  risk_level: string;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  top_risks: Array<{
    title: string;
    severity: string;
    risk_score: number;
    resource_name: string;
    resource_type: string;
  }>;
  recommendations: string[];
}

export interface ApiResponse<T = any> {
  data?: T;
  error?: string;
  message?: string;
}
