import React, { useState } from 'react';

type Issue = {
  type: string;
  message: string;
};

type Result = {
  domain: string;
  issues: Issue[];
  riskScore: number;
};

function getRiskColor(score: number): string {
  if (score <= 30) return 'bg-green-100 text-green-800 border-green-300';
  if (score <= 70) return 'bg-yellow-100 text-yellow-800 border-yellow-300';
  return 'bg-red-100 text-red-800 border-red-300';
}

const App: React.FC = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch(`http://localhost:3000/analyze?url=${encodeURIComponent(url)}`);
      const data = await res.json();
      setResult(data);
    } catch (error) {
      alert('Error analyzing URL');
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-white flex items-center justify-center px-4 py-8">
      <div className="w-full max-w-3xl bg-white rounded-xl shadow-lg p-8">
        <h1 className="text-4xl font-extrabold text-center mb-6 text-blue-800">Phishing Detector</h1>

        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-8">
          <input
            type="text"
            placeholder="e.g. example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="w-full sm:w-96 p-3 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading || !url}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6 py-3 rounded transition disabled:opacity-50"
          >
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>

        {result && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">Results for <span className="font-mono text-blue-600">{result.domain}</span></h2>
              <span className={`px-4 py-1 text-sm font-bold rounded-full border ${getRiskColor(result.riskScore)}`}>
                Risk Score: {result.riskScore}/100
              </span>
            </div>

            <table className="table-auto w-full border border-gray-300 rounded overflow-hidden text-sm">
              <thead className="bg-gray-100 text-left">
                <tr>
                  <th className="px-4 py-2 border-b">Type</th>
                  <th className="px-4 py-2 border-b">Message</th>
                </tr>
              </thead>
              <tbody>
                {result.issues.map((issue, idx) => (
                  <tr key={idx} className="odd:bg-white even:bg-gray-50">
                    <td className="px-4 py-2 border-b font-mono text-blue-900">{issue.type}</td>
                    <td className="px-4 py-2 border-b text-gray-700">{issue.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
