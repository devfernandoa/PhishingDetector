// src/App.tsx
import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { issueExplanations } from './issueExplanations';
import { ExportButton } from './components/ExportButton';

const RISK_COLORS = ['#22c55e', '#eab308', '#ef4444'];

const getRiskColor = (score: number): string => {
  if (score <= 30) return RISK_COLORS[0];
  if (score <= 70) return RISK_COLORS[1];
  return RISK_COLORS[2];
};

const App: React.FC = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<any | null>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem('scan-history');
    if (saved) setHistory(JSON.parse(saved));
  }, []);

  useEffect(() => {
    localStorage.setItem('scan-history', JSON.stringify(history));
  }, [history]);

  const handleAnalyze = async () => {
    setLoading(true);
    const res = await fetch(`http://localhost:3000/analyze?url=${encodeURIComponent(url)}`);
    const data = await res.json();
    setResult(data);
    setHistory(prev => [...prev, { ...data, timestamp: new Date().toISOString() }]);
    setLoading(false);
  };

  const issueStats = history.flatMap(h => h.issues.map((i: any) => i.type));
  const chartData = [...new Set(issueStats)].map(type => ({
    name: type,
    count: issueStats.filter(t => t === type).length
  }));

  return (
    <div className="min-h-screen bg-gray-100 p-6">
      <div className="max-w-5xl mx-auto bg-white shadow rounded-xl p-6">
        <h1 className="text-3xl font-bold mb-4 text-center">Phishing Analysis Dashboard</h1>

        <div className="flex flex-col sm:flex-row gap-4 mb-6">
          <input
            className="border p-3 flex-1 rounded"
            placeholder="Enter a URL"
            value={url}
            onChange={e => setUrl(e.target.value)}
          />
          <button
            className="bg-blue-600 text-white px-6 py-3 rounded hover:bg-blue-700"
            onClick={handleAnalyze}
            disabled={loading}
          >
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>

        {result && (
          <div className="mb-8">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-xl font-semibold">Result for <span className="font-mono text-blue-600">{result.domain}</span></h2>
              <span
                className="px-4 py-1 font-bold text-sm rounded-full"
                style={{ backgroundColor: getRiskColor(result.riskScore), color: 'white' }}
              >
                Risk Score: {result.riskScore}/100
              </span>
            </div>
            <table className="table-auto w-full text-sm border">
              <thead className="bg-gray-100">
                <tr>
                  <th className="px-4 py-2 text-left">Type</th>
                  <th className="px-4 py-2 text-left">Message</th>
                  <th className="px-4 py-2 text-left">Explanation</th>
                </tr>
              </thead>
              <tbody>
                {result.issues.map((issue: any, idx: number) => (
                  <tr key={idx} className="border-t">
                    <td className="px-4 py-2 font-mono text-blue-800">{issue.type}</td>
                    <td className="px-4 py-2">{issue.message}</td>
                    <td className="px-4 py-2 text-gray-600 italic">
                      {issueExplanations[issue.type] || 'No explanation available.'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {history.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="bg-white p-4 border rounded">
              <h3 className="font-bold mb-2">Issue Type Distribution</h3>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={chartData}>
                  <XAxis dataKey="name" fontSize={10} />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#3b82f6" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="bg-white p-4 border rounded">
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-bold">URL History</h3>
                <ExportButton data={history} />
              </div>
              <ul className="text-sm max-h-60 overflow-auto">
                {history.slice().reverse().map((h, i) => (
                  <li key={i} className="border-t py-1">
                    <span className="text-blue-600 font-mono">{h.domain}</span>
                    <span className="ml-2">({h.riskScore})</span>
                    <span className="ml-2 text-gray-400 text-xs">{new Date(h.timestamp).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;