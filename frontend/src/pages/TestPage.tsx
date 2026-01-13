import React from 'react';

const TestPage: React.FC = () => {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-blue-600">Test Page Working!</h1>
      <p className="mt-4">If you can see this, the frontend is working.</p>
      <button 
        className="mt-4 bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
        onClick={() => alert('Button clicked!')}
      >
        Test Button
      </button>
    </div>
  );
};

export default TestPage;
