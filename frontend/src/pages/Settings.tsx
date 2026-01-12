import React, { useState } from 'react';
import { Settings as SettingsIcon, Shield, Database, Bell, User } from 'lucide-react';

const Settings: React.FC = () => {
  const [apiUrl, setApiUrl] = useState('http://localhost:8000');
  const [notifications, setNotifications] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(30);

  const handleSave = () => {
    // Save settings to localStorage or backend
    localStorage.setItem('cspm-settings', JSON.stringify({
      apiUrl,
      notifications,
      autoRefresh,
      refreshInterval
    }));
    
    alert('Settings saved successfully!');
  };

  const handleReset = () => {
    setApiUrl('http://localhost:8000');
    setNotifications(true);
    setAutoRefresh(true);
    setRefreshInterval(30);
    localStorage.removeItem('cspm-settings');
  };

  return (
    <div className="space-y-6">
      <div className="card">
        <h2 className="text-xl font-semibold text-gray-900 mb-6 flex items-center">
          <SettingsIcon className="w-6 h-6 mr-2 text-primary-600" />
          Settings
        </h2>

        <div className="space-y-8">
          {/* API Configuration */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
              <Shield className="w-5 h-5 mr-2 text-primary-600" />
              API Configuration
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  API Base URL
                </label>
                <input
                  type="url"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  className="input"
                  placeholder="http://localhost:8000"
                />
                <p className="mt-1 text-sm text-gray-500">
                  The base URL for the CSPM Scanner API
                </p>
              </div>
            </div>
          </div>

          {/* Notification Settings */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
              <Bell className="w-5 h-5 mr-2 text-primary-600" />
              Notifications
            </h3>
            <div className="space-y-4">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="notifications"
                  checked={notifications}
                  onChange={(e) => setNotifications(e.target.checked)}
                  className="rounded border-gray-300 text-primary-600 focus:ring-primary-500 mr-3"
                />
                <label htmlFor="notifications" className="text-sm font-medium text-gray-700">
                  Enable desktop notifications
                </label>
              </div>
              <p className="text-sm text-gray-500">
                Receive notifications when scans complete or fail
              </p>
            </div>
          </div>

          {/* Data Management */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
              <Database className="w-5 h-5 mr-2 text-primary-600" />
              Data Management
            </h3>
            <div className="space-y-4">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="autoRefresh"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                  className="rounded border-gray-300 text-primary-600 focus:ring-primary-500 mr-3"
                />
                <label htmlFor="autoRefresh" className="text-sm font-medium text-gray-700">
                  Auto-refresh data
                </label>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Refresh Interval (seconds)
                </label>
                <input
                  type="number"
                  min="10"
                  max="300"
                  value={refreshInterval}
                  onChange={(e) => setRefreshInterval(parseInt(e.target.value))}
                  className="input"
                  disabled={!autoRefresh}
                />
                <p className="mt-1 text-sm text-gray-500">
                  How often to refresh scan data (10-300 seconds)
                </p>
              </div>
            </div>
          </div>

          {/* User Preferences */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
              <User className="w-5 h-5 mr-2 text-primary-600" />
              User Preferences
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Default Severity Filter
                </label>
                <select className="input">
                  <option value="all">All Severities</option>
                  <option value="critical">Critical Only</option>
                  <option value="high">High and Above</option>
                  <option value="medium">Medium and Above</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Theme
                </label>
                <select className="input">
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                  <option value="system">System</option>
                </select>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex space-x-4 pt-6 border-t border-gray-200">
            <button
              onClick={handleSave}
              className="btn btn-primary"
            >
              Save Settings
            </button>
            <button
              onClick={handleReset}
              className="btn btn-secondary"
            >
              Reset to Defaults
            </button>
          </div>
        </div>
      </div>

      {/* Information Card */}
      <div className="card">
        <h3 className="text-lg font-medium text-gray-900 mb-4">About</h3>
        <div className="space-y-3 text-sm text-gray-600">
          <div>
            <strong>Cloud Security Posture Scanner</strong>
          </div>
          <div>
            <strong>Version:</strong> 1.0.0
          </div>
          <div>
            <strong>Description:</strong> Azure security misconfiguration detector
          </div>
          <div>
            <strong>Features:</strong>
            <ul className="list-disc list-inside mt-2 space-y-1">
              <li>Multi-resource security scanning</li>
              <li>Risk assessment and scoring</li>
              <li>Interactive reports and dashboards</li>
              <li>Real-time scan monitoring</li>
              <li>Export capabilities (JSON/HTML)</li>
            </ul>
          </div>
          <div>
            <strong>Supported Resources:</strong>
            <ul className="list-disc list-inside mt-2 space-y-1">
              <li>Storage Accounts</li>
              <li>Network Security Groups</li>
              <li>Key Vaults</li>
              <li>Virtual Machines & Disks</li>
              <li>Databricks Workspaces</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
