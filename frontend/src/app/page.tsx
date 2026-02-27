'use client';
import React, { useState, useMemo } from 'react';
import axios from 'axios';
import StatsFilters from '@/components/StatsFilters';
import LogTable from '@/components/LogTable';
import { ShieldCheck, UploadCloud, Lock } from 'lucide-react';
// ... (Keep your LineChart imports)

export default function SOCDashboard() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [logs, setLogs] = useState<any[]>([]);
  const [batchId, setBatchId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeFilter, setFilter] = useState('all');

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    // ... (Keep your existing axios logic)
    // Update: setBatchId(response.data.batch_id);
    // Update: setLogs(response.data.data);
  };

  // --- NEW: Memoized Filtering Logic ---
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      if (activeFilter === 'all') return true;
      if (activeFilter === 'anomalies') return log.is_anomaly;
      if (activeFilter === 'brute_force') return log.anomaly_reason?.includes('Brute Force');
      if (activeFilter === 'sensitive') return log.anomaly_reason?.includes('sensitive endpoint');
      if (activeFilter === 'ml') return log.anomaly_reason?.includes('ML Model');
      return true;
    });
  }, [logs, activeFilter]);

  if (!isLoggedIn) { /* ... keep login screen ... */ }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-300 p-8">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header Section */}
        <div className="flex justify-between items-center border-b border-slate-700 pb-4">
          <div className="flex items-center">
            <ShieldCheck className="text-emerald-500 w-8 h-8 mr-3" />
            <h1 className="text-2xl font-bold text-white">TENEX SOC Analyst Dashboard</h1>
          </div>
          <div className="relative overflow-hidden inline-block">
            <button className="bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2 px-6 rounded shadow-lg flex items-center transition-all">
              <UploadCloud className="w-5 h-5 mr-2" />
              {loading ? 'AI Processing...' : 'Upload Log'}
            </button>
            <input type="file" onChange={handleFileUpload} className="absolute left-0 top-0 opacity-0 cursor-pointer h-full w-full" />
          </div>
        </div>

        {logs.length > 0 && (
          <>
            {/* Timeline logic here... */}

            <StatsFilters
              batchId={batchId}
              activeFilter={activeFilter}
              setFilter={setFilter}
              totalLogs={logs.length}
            />

            <LogTable logs={filteredLogs} />
          </>
        )}
      </div>
    </div>
  );
}