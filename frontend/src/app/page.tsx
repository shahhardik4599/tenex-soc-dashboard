'use client';

import React, { useState, useMemo } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { UploadCloud, ShieldCheck } from 'lucide-react';

// New Component Imports
import AuthContainer from '@/components/AuthContainer';
import StatsFilters from '@/components/StatsFilters';
import LogTable from '@/components/LogTable';

export default function SOCDashboard() {
  // Authentication State
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [credentials, setCredentials] = useState({ username: '', password: '' });

  // Data State
  const [logs, setLogs] = useState<any[]>([]);
  const [batchId, setBatchId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Filter State
  const [activeFilter, setFilter] = useState('all');

  // --- Auth Success Handler ---
  const handleLoginSuccess = (creds: any) => {
    setCredentials(creds);
    setIsLoggedIn(true);
  };

  // --- File Upload Handler ---
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;

    setLoading(true);
    setError('');
    const file = e.target.files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
      const authHeader = 'Basic ' + btoa(`${credentials.username}:${credentials.password}`);

      const response = await axios.post('http://localhost:8000/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Authorization': authHeader
        }
      });

      // Update state with new batch info
      setBatchId(response.data.batch_id);

      // Sort logs so anomalies are at the top initially
      const sortedLogs = response.data.data.sort((a: any, b: any) =>
        (b.is_anomaly === true ? 1 : 0) - (a.is_anomaly === true ? 1 : 0)
      );
      setLogs(sortedLogs);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to upload and process file.');
      if (err.response?.status === 401) {
        setIsLoggedIn(false);
        alert("Session expired. Please log in again.");
      }
    } finally {
      setLoading(false);
    }
  };

  // --- Filtering Logic ---
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

  // --- Timeline Chart Data Prep ---
  const chartData = useMemo(() => {
    return logs.reduce((acc: any[], log: any) => {
      const time = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const existing = acc.find(item => item.time === time);
      if (existing) {
        existing.events += 1;
        if (log.is_anomaly) existing.anomalies += 1;
      } else {
        acc.push({ time, events: 1, anomalies: log.is_anomaly ? 1 : 0 });
      }
      return acc;
    }, []).reverse();
  }, [logs]);

  // ==========================================
  // AUTH GUARD
  // ==========================================
  if (!isLoggedIn) {
    return <AuthContainer onLoginSuccess={handleLoginSuccess} />;
  }

  // ==========================================
  // SOC ANALYST DASHBOARD
  // ==========================================
  return (
    <div className="min-h-screen bg-slate-900 text-slate-300 p-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-8">

        {/* Header */}
        <div className="flex justify-between items-center border-b border-slate-700 pb-4">
          <div className="flex items-center">
            <ShieldCheck className="text-emerald-500 w-8 h-8 mr-3" />
            <h1 className="text-2xl font-bold text-white">TENEX SOC Dashboard</h1>
          </div>
          <div className="relative overflow-hidden inline-block">
            <button className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2 px-6 rounded shadow-lg flex items-center transition-all">
              <UploadCloud className="w-5 h-5 mr-2" />
              {loading ? 'AI Engine Processing...' : 'Upload Access Log'}
            </button>
            <input
              type="file"
              accept=".log,.txt"
              onChange={handleFileUpload}
              disabled={loading}
              className="absolute left-0 top-0 opacity-0 cursor-pointer h-full w-full"
            />
          </div>
        </div>

        {error && <div className="bg-red-900/50 border border-red-500 text-red-200 p-4 rounded">{error}</div>}

        {logs.length > 0 && (
          <>
            {/* Timeline Chart */}
            <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg">
              <h2 className="text-lg font-semibold text-white mb-4">Event Timeline (Velocity & Anomalies)</h2>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="time" stroke="#94a3b8" />
                    <YAxis stroke="#94a3b8" />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#475569' }} />
                    <Line type="monotone" dataKey="events" stroke="#10b981" strokeWidth={2} name="Total Events" dot={false} />
                    <Line type="monotone" dataKey="anomalies" stroke="#ef4444" strokeWidth={2} name="Anomalies" />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Filter Buttons & Batch Info */}
            <StatsFilters
              batchId={batchId}
              activeFilter={activeFilter}
              setFilter={setFilter}
              totalLogs={logs.length}
            />

            {/* Modular Results Table */}
            <LogTable logs={filteredLogs} />
          </>
        )}
      </div>
    </div>
  );
}