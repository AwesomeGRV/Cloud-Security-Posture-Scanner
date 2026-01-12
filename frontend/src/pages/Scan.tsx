import React, { useState, useEffect } from 'react';
import { Shield, Play, AlertCircle, CheckCircle } from 'lucide-react';
import { apiService } from '../services/api';
import { Subscription, ScanRequest, ScanStatus } from '../types';

const Scan: React.FC = () => {
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [selectedSubscription, setSelectedSubscription] = useState<string>('');
  const [selectedResourceTypes, setSelectedResourceTypes] = useState<string[]>([]);
  const [severityThreshold, setSeverityThreshold] = useState<string>('low');
  const [isScanning, setIsScanning] = useState(false);
  const [currentScan, setCurrentScan] = useState<ScanStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const resourceTypes = [
    'Microsoft.Storage/storageAccounts',
    'Microsoft.Network/networkSecurityGroups',
    'Microsoft.KeyVault/vaults',
    'Microsoft.Compute/virtualMachines',
    'Microsoft.Databricks/workspaces'
  ];

  const severityLevels = ['info', 'low', 'medium', 'high', 'critical'];

  useEffect(() => {
    loadSubscriptions();
  }, []);

  useEffect(() => {
    if (currentScan && currentScan.status === 'running') {
      const interval = setInterval(async () => {
        try {
          const status = await apiService.getScanStatus(currentScan.scan_id);
          setCurrentScan(status);
          
          if (status.status === 'completed' || status.status === 'failed') {
            setIsScanning(false);
            clearInterval(interval);
          }
        } catch (err) {
          console.error('Error checking scan status:', err);
          clearInterval(interval);
        }
      }, 3000);

      return () => clearInterval(interval);
    }
  }, [currentScan]);

  const loadSubscriptions = async () => {
    try {
      setLoading(true);
      const subs = await apiService.getSubscriptions();
      setSubscriptions(subs.filter(sub => sub.state === 'Enabled'));
    } catch (err) {
      setError('Failed to load subscriptions');
      console.error('Error loading subscriptions:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStartScan = async () => {
    if (!selectedSubscription && subscriptions.length > 0) {
      setError('Please select a subscription to scan');
      return;
    }

    try {
      setIsScanning(true);
      setError(null);

      const scanRequest: ScanRequest = {
        subscription_id: selectedSubscription || undefined,
        resource_types: selectedResourceTypes.length > 0 ? selectedResourceTypes : undefined,
        severity_threshold: severityThreshold as any
      };

      const response = await apiService.startScan(scanRequest);
      const status = await apiService.getScanStatus(response.scan_id);
      setCurrentScan(status);

    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to start scan');
      setIsScanning(false);
    }
  };

  const handleResourceTypeChange = (resourceType: string) => {
    setSelectedResourceTypes(prev => 
      prev.includes(resourceType)
        ? prev.filter(rt => rt !== resourceType)
        : [...prev, resourceType]
    );
  };

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: 'text-danger-600 bg-danger-50 border-danger-200',
      high: 'text-warning-600 bg-warning-50 border-warning-200',
      medium: 'text-primary-600 bg-primary-50 border-primary-200',
      low: 'text-success-600 bg-success-50 border-success-200',
      info: 'text-gray-600 bg-gray-50 border-gray-200'
    };
    return colors[severity as keyof typeof colors] || colors.info;
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
      {/* Scan Configuration */}
      <div className="card">
        <h2 className="text-xl font-semibold text-gray-900 mb-6 flex items-center">
          <Shield className="w-6 h-6 mr-2 text-primary-600" />
          Security Scan Configuration
        </h2>

        {error && (
          <div className="mb-6 bg-danger-50 border border-danger-200 text-danger-700 px-4 py-3 rounded-lg flex items-center">
            <AlertCircle className="w-5 h-5 mr-2" />
            {error}
          </div>
        )}

        {/* Subscription Selection */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Azure Subscription
          </label>
          <select
            value={selectedSubscription}
            onChange={(e) => setSelectedSubscription(e.target.value)}
            className="input"
          >
            <option value="">Scan All Subscriptions</option>
            {subscriptions.map(sub => (
              <option key={sub.id} value={sub.id}>
                {sub.display_name} ({sub.id.substring(0, 8)}...)
              </option>
            ))}
          </select>
        </div>

        {/* Resource Types */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Resource Types to Scan
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {resourceTypes.map(resourceType => (
              <label key={resourceType} className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={selectedResourceTypes.includes(resourceType)}
                  onChange={() => handleResourceTypeChange(resourceType)}
                  className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                />
                <span className="text-sm text-gray-700">{resourceType}</span>
              </label>
            ))}
          </div>
          <p className="mt-2 text-sm text-gray-500">
            Leave empty to scan all supported resource types
          </p>
        </div>

        {/* Severity Threshold */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Minimum Severity Level
          </label>
          <div className="flex space-x-4">
            {severityLevels.map(severity => (
              <label key={severity} className="flex items-center cursor-pointer">
                <input
                  type="radio"
                  name="severity"
                  value={severity}
                  checked={severityThreshold === severity}
                  onChange={(e) => setSeverityThreshold(e.target.value)}
                  className="mr-2"
                />
                <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getSeverityColor(severity)}`}>
                  {severity.toUpperCase()}
                </span>
              </label>
            ))}
          </div>
        </div>

        {/* Start Scan Button */}
        <button
          onClick={handleStartScan}
          disabled={isScanning}
          className="btn btn-primary flex items-center"
        >
          {isScanning ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
              Scanning...
            </>
          ) : (
            <>
              <Play className="w-4 h-4 mr-2" />
              Start Security Scan
            </>
          )}
        </button>
      </div>

      {/* Scan Progress */}
      {currentScan && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Scan Progress</h3>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                {currentScan.status === 'completed' ? (
                  <CheckCircle className="w-5 h-5 text-success-600 mr-2" />
                ) : currentScan.status === 'failed' ? (
                  <AlertCircle className="w-5 h-5 text-danger-600 mr-2" />
                ) : (
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary-600 mr-2"></div>
                )}
                <span className="font-medium capitalize">{currentScan.status}</span>
              </div>
              <span className="text-sm text-gray-500">
                {currentScan.progress}% Complete
              </span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-gray-200 rounded-full h-3">
              <div 
                className="bg-primary-600 h-3 rounded-full transition-all duration-300"
                style={{ width: `${currentScan.progress}%` }}
              ></div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-500">Scan ID:</span>
                <span className="ml-2 font-mono">{currentScan.scan_id.substring(0, 8)}...</span>
              </div>
              <div>
                <span className="text-gray-500">Started:</span>
                <span className="ml-2">
                  {new Date(currentScan.started_at).toLocaleString()}
                </span>
              </div>
            </div>

            {currentScan.error_message && (
              <div className="bg-danger-50 border border-danger-200 text-danger-700 px-4 py-3 rounded-lg">
                <strong>Error:</strong> {currentScan.error_message}
              </div>
            )}

            {currentScan.status === 'completed' && (
              <div className="bg-success-50 border border-success-200 text-success-700 px-4 py-3 rounded-lg">
                <CheckCircle className="w-5 h-5 inline mr-2" />
                Scan completed successfully! Check the Reports section for detailed results.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recent Scans */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Scans</h3>
        <p className="text-gray-600">
          View and manage your recent security scans in the Activity tab.
        </p>
      </div>
    </div>
  );
};

export default Scan;
