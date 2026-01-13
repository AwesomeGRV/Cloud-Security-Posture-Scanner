import React, { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';

const DashboardSimple: React.FC = () => {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      console.log('Starting API test...');
      
      // Test direct fetch
      const response = await fetch('/subscriptions');
      console.log('Response status:', response.status);
      const result = await response.json();
      console.log('API result:', result);
      setData(result);
      
    } catch (err) {
      console.error('Error:', err);
      setError('Failed to load data: ' + (err instanceof Error ? err.message : 'Unknown error'));
    }
  };

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <h2 className="text-red-800 text-lg font-semibold">Error</h2>
          <p className="text-red-600">{error}</p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary-600"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 flex items-center">
          <Shield className="w-8 h-8 mr-3 text-primary-600" />
          Simple Dashboard Test
        </h1>
      </div>
      
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold mb-4">API Data Loaded Successfully!</h2>
        <pre className="bg-gray-100 p-4 rounded overflow-auto">
          {JSON.stringify(data, null, 2)}
        </pre>
      </div>
    </div>
  );
};

export default DashboardSimple;
