import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Activity, TrendingUp } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { apiService } from '../services/api';
import { ScanResult, ScanStatus } from '../types';

const Dashboard: React.FC = () => {
  const [recentScans, setRecentScans] = useState<ScanStatus[]>([]);
  const [latestResults, setLatestResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      const [scans] = await Promise.all([
        apiService.listScans(),
        apiService.listReports()
      ]);

      setRecentScans(scans.slice(0, 5));

      // Load results for completed scans
      const completedScans = scans.filter(scan => scan.status === 'completed');
      const results = await Promise.all(
        completedScans.slice(0, 3).map(scan => 
          apiService.getScanResult(scan.scan_id)
        )
      );
      setLatestResults(results);

    } catch (err) {
      setError('Failed to load dashboard data');
      console.error('Dashboard error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#d97706',
      medium: '#2563eb',
      low: '#16a34a',
      info: '#6b7280'
    };
    return colors[severity as keyof typeof colors] || '#6b7280';
  };

  const getRiskLevel = (score: number) => {
    if (score >= 80) return { level: 'Critical', color: 'text-danger-600' };
    if (score >= 60) return { level: 'High', color: 'text-warning-600' };
    if (score >= 40) return { level: 'Medium', color: 'text-primary-600' };
    if (score >= 20) return { level: 'Low', color: 'text-success-600' };
    return { level: 'Minimal', color: 'text-gray-600' };
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-danger-50 border border-danger-200 text-danger-700 px-4 py-3 rounded-lg">
        {error}
      </div>
    );
  }

  // Calculate overall stats
  const totalFindings = latestResults.reduce((sum, result) => sum + result.total_findings, 0);
  const avgRiskScore = latestResults.length > 0 
    ? Math.round(latestResults.reduce((sum, result) => sum + result.risk_score, 0) / latestResults.length)
    : 0;

  const riskData = latestResults.map(result => ({
    name: result.subscription_name || result.subscription_id.substring(0, 8),
    riskScore: result.risk_score,
    findings: result.total_findings
  }));

  const severityData = latestResults.reduce((acc, result) => {
    Object.entries(result.findings_by_severity).forEach(([severity, count]) => {
      const existing = acc.find(item => item.name === severity);
      if (existing) {
        existing.value += count;
      } else {
        acc.push({ name: severity, value: count });
      }
    });
    return acc;
  }, [] as { name: string; value: number }[]);

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center">
            <div className="p-3 bg-primary-100 rounded-lg">
              <Shield className="w-6 h-6 text-primary-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Risk Score</p>
              <p className="text-2xl font-bold text-gray-900">{avgRiskScore}</p>
              <p className={`text-sm ${getRiskLevel(avgRiskScore).color}`}>
                {getRiskLevel(avgRiskScore).level}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="p-3 bg-warning-100 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-warning-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Total Findings</p>
              <p className="text-2xl font-bold text-gray-900">{totalFindings}</p>
              <p className="text-sm text-gray-500">Across all scans</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="p-3 bg-success-100 rounded-lg">
              <CheckCircle className="w-6 h-6 text-success-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Completed Scans</p>
              <p className="text-2xl font-bold text-gray-900">
                {recentScans.filter(s => s.status === 'completed').length}
              </p>
              <p className="text-sm text-gray-500">Last 30 days</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="p-3 bg-blue-100 rounded-lg">
              <Activity className="w-6 h-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Active Scans</p>
              <p className="text-2xl font-bold text-gray-900">
                {recentScans.filter(s => s.status === 'running').length}
              </p>
              <p className="text-sm text-gray-500">In progress</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Score Chart */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Scores by Subscription</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={riskData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="riskScore" fill="#3b82f6" name="Risk Score" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Findings by Severity</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={getSeverityColor(entry.name)} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Recent Scans</h3>
          <TrendingUp className="w-5 h-5 text-gray-400" />
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Scan ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Progress
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Started
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {recentScans.map((scan) => (
                <tr key={scan.scan_id}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    {scan.scan_id.substring(0, 8)}...
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      scan.status === 'completed' ? 'bg-success-100 text-success-800' :
                      scan.status === 'running' ? 'bg-primary-100 text-primary-800' :
                      scan.status === 'failed' ? 'bg-danger-100 text-danger-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="flex-1 bg-gray-200 rounded-full h-2 mr-2">
                        <div 
                          className="bg-primary-600 h-2 rounded-full" 
                          style={{ width: `${scan.progress}%` }}
                        ></div>
                      </div>
                      <span className="text-sm text-gray-600">{scan.progress}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(scan.started_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
