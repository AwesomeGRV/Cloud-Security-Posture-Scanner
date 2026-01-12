import axios from 'axios';
import {
  Subscription,
  ScanRequest,
  ScanStartResponse,
  ScanStatus,
  ScanResult,
  Report,
  ReportStatistics
} from '../types';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export const apiService = {
  // Health check
  async healthCheck() {
    const response = await api.get('/health');
    return response.data;
  },

  // Subscriptions
  async getSubscriptions(): Promise<Subscription[]> {
    const response = await api.get('/subscriptions');
    return response.data;
  },

  // Scanning
  async startScan(scanRequest: ScanRequest): Promise<ScanStartResponse> {
    const response = await api.post('/scan/start', scanRequest);
    return response.data;
  },

  async getScanStatus(scanId: string): Promise<ScanStatus> {
    const response = await api.get(`/scan/${scanId}/status`);
    return response.data;
  },

  async getScanResult(scanId: string): Promise<ScanResult> {
    const response = await api.get(`/scan/${scanId}/result`);
    return response.data;
  },

  async downloadScanReport(scanId: string, format: 'json' | 'html' = 'json'): Promise<Blob> {
    const response = await api.get(`/scan/${scanId}/report?format=${format}`, {
      responseType: 'blob',
    });
    return response.data;
  },

  async listScans(): Promise<ScanStatus[]> {
    const response = await api.get('/scans');
    return response.data;
  },

  async deleteScan(scanId: string): Promise<void> {
    await api.delete(`/scan/${scanId}`);
  },

  // Reports
  async listReports(): Promise<{ reports: Report[]; statistics: ReportStatistics }> {
    const response = await api.get('/reports');
    return response.data;
  },

  async downloadReport(filename: string): Promise<Blob> {
    const response = await api.get(`/reports/${filename}`, {
      responseType: 'blob',
    });
    return response.data;
  },

  async cleanupOldReports(daysToKeep: number = 30): Promise<{ message: string; deleted_count: number }> {
    const response = await api.delete(`/reports/cleanup?days_to_keep=${daysToKeep}`);
    return response.data;
  },

  // Configuration
  async getSupportedResourceTypes(): Promise<string[]> {
    const response = await api.get('/resource-types');
    return response.data;
  },

  async getSeverityLevels(): Promise<string[]> {
    const response = await api.get('/severity-levels');
    return response.data;
  },
};

export default api;
