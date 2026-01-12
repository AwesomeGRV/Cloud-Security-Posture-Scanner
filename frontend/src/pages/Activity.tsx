import React, { useState, useEffect } from 'react';
import { Activity as ActivityIcon, Clock, CheckCircle, AlertCircle, XCircle } from 'lucide-react';
import { apiService } from '../services/api';
import { ScanStatus } from '../types';

const Activity: React.FC = () => {
  const [scans, setScans] = useState<ScanStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadScans = async () => {
    try {
      const scanData = await apiService.listScans();
      setScans(scanData.sort((a, b) => 
        new Date(b.started_at).getTime() - new Date(a.started_at).getTime()
      ));
    } catch (err) {
      setError('Failed to load scan activity');
      console.error('Error loading scans:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteScan = async (scanId: string) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      try {
        await apiService.deleteScan(scanId);
        loadScans();
      } catch (err) {
        console.error('Error deleting scan:', err);
      }
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-success-600" />;
      case 'running':
        return <ActivityIcon className="w-5 h-5 text-primary-600 animate-pulse" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-danger-600" />;
      default:
        return <Clock className="w-5 h-5 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-success-100 text-success-800';
      case 'running':
        return 'bg-primary-100 text-primary-800';
      case 'failed':
        return 'bg-danger-100 text-danger-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const formatDuration = (startedAt: string, completedAt?: string) => {
    const start = new Date(startedAt);
    const end = completedAt ? new Date(completedAt) : new Date();
    const duration = Math.floor((end.getTime() - start.getTime()) / 1000);
    
    if (duration < 60) return `${duration}s`;
    if (duration < 3600) return `${Math.floor(duration / 60)}m ${duration % 60}s`;
    return `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="card">
        <h2 className="text-xl font-semibold text-gray-900 mb-6 flex items-center">
          <ActivityIcon className="w-6 h-6 mr-2 text-primary-600" />
          Scan Activity
        </h2>

        {error && (
          <div className="mb-6 bg-danger-50 border border-danger-200 text-danger-700 px-4 py-3 rounded-lg flex items-center">
            <AlertCircle className="w-5 h-5 mr-2" />
            {error}
          </div>
        )}

        {scans.length === 0 ? (
          <div className="text-center py-12">
            <Clock className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No scan activity</h3>
            <p className="text-gray-500">
              Start a security scan to see activity here.
            </p>
          </div>
        ) : (
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
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Duration
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {scans.map((scan) => (
                  <tr key={scan.scan_id}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-mono text-gray-900">
                        {scan.scan_id.substring(0, 8)}...
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(scan.status)}
                        <span className={`ml-2 inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-1 bg-gray-200 rounded-full h-2 mr-2 max-w-xs">
                          <div 
                            className="bg-primary-600 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${scan.progress}%` }}
                          ></div>
                        </div>
                        <span className="text-sm text-gray-600">{scan.progress}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(scan.started_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {formatDuration(scan.started_at, scan.completed_at)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        {scan.status === 'completed' && (
                          <button
                            onClick={() => window.open(`/scan/${scan.scan_id}/report`, '_blank')}
                            className="text-primary-600 hover:text-primary-900"
                          >
                            View Report
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteScan(scan.scan_id)}
                          className="text-danger-600 hover:text-danger-900"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
          <div className="text-center">
            <div className="text-3xl font-bold text-primary-600">
              {scans.filter(s => s.status === 'running').length}
            </div>
            <div className="text-sm text-gray-600 mt-1">Running Scans</div>
          </div>
        </div>
        
        <div className="card">
          <div className="text-center">
            <div className="text-3xl font-bold text-success-600">
              {scans.filter(s => s.status === 'completed').length}
            </div>
            <div className="text-sm text-gray-600 mt-1">Completed Scans</div>
          </div>
        </div>
        
        <div className="card">
          <div className="text-center">
            <div className="text-3xl font-bold text-danger-600">
              {scans.filter(s => s.status === 'failed').length}
            </div>
            <div className="text-sm text-gray-600 mt-1">Failed Scans</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Activity;
