'use client';

import React, { useState, useMemo } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { UploadCloud, ShieldCheck, ChevronLeft, ChevronRight } from 'lucide-react';

// Component Imports
import AuthContainer from '@/components/AuthContainer';
import StatsFilters from '@/components/StatsFilters';
import LogTable from '@/components/LogTable';
import CyberLoader from '@/components/Loader';
import ThreatChart from '@/components/ThreatChart';

export default function SOCDashboard() {
  // --- State Management ---
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [logs, setLogs] = useState<any[]>([]);
  const [batchId, setBatchId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeFilter, setFilter] = useState('all');

  // --- Pagination State ---
  const [currentPage, setCurrentPage] = useState(1);
  const rowsPerPage = 10;

  // --- Handlers ---
  const handleLoginSuccess = (creds: any) => {
    setCredentials(creds);
    setIsLoggedIn(true);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;

    setLoading(true);
    setError('');
    setCurrentPage(1); // Reset to page 1 on new upload
    const file = e.target.files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
      const authHeader = 'Basic ' + btoa(`${credentials.username}:${credentials.password}`);
      const response = await axios.post('http://localhost:8000/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data', 'Authorization': authHeader }
      });

      setBatchId(response.data.batch_id);
      setLogs(response.data.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to process logs.');
      if (err.response?.status === 401) setIsLoggedIn(false);
    } finally {
      setLoading(false);
    }
  };

  // --- Filtering & Pagination Logic ---
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      if (activeFilter === 'all') return true;
      if (activeFilter === 'anomalies') return log.is_anomaly;
      if (activeFilter === 'brute_force') return log.category === 'Brute Force';
      if (activeFilter === 'sensitive') return log.category === 'Probing';
      if (activeFilter === 'ml') return log.category === 'ML Behavioral';
      return true;
    });
  }, [logs, activeFilter]);

  const totalPages = Math.ceil(filteredLogs.length / rowsPerPage);
  const paginatedLogs = filteredLogs.slice(
    (currentPage - 1) * rowsPerPage,
    currentPage * rowsPerPage
  );

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

  // --- Auth Guard ---
  if (!isLoggedIn) {
    return <AuthContainer onLoginSuccess={handleLoginSuccess} />;
  }

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
            <button className={`bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2 px-6 rounded shadow-lg flex items-center transition-all ${loading ? 'opacity-50' : ''}`}>
              <UploadCloud className="w-5 h-5 mr-2" />
              {loading ? 'AI Engine Processing...' : 'Upload Access Log'}
            </button>
            <input type="file" accept=".log,.txt" onChange={handleFileUpload} disabled={loading} className="absolute left-0 top-0 opacity-0 cursor-pointer h-full w-full" />
          </div>
        </div>

        {error && <div className="bg-red-900/50 border border-red-500 text-red-200 p-4 rounded">{error}</div>}

        {loading ? (
          <CyberLoader />
        ) : logs.length > 0 ? (
          <>
            {/* Timeline Chart - Re-integrated */}
            {/* <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg">
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
            </div> */}
              {logs.length > 0 && (
                <>
                  {/* PASS FILTERED LOGS HERE INSTEAD OF ALL LOGS */}
                  <ThreatChart logs={filteredLogs} />

                  <StatsFilters
                    batchId={batchId}
                    activeFilter={activeFilter}
                    setFilter={(f) => { setFilter(f); setCurrentPage(1); }}
                    totalLogs={logs.length}
                  />

                  <div className="space-y-4">
                    <LogTable logs={paginatedLogs} />
                    {/* ... pagination controls ... */}
                  </div>
                </>
              )}

            <StatsFilters
              batchId={batchId}
              activeFilter={activeFilter}
              setFilter={(f) => { setFilter(f); setCurrentPage(1); }}
              totalLogs={logs.length}
            />

            <div className="space-y-4">
              <LogTable logs={paginatedLogs} />

              {/* Pagination Controls */}
              <div className="flex justify-between items-center bg-slate-800 p-4 rounded-xl border border-slate-700">
                <div className="text-sm text-slate-400">
                  Showing <span className="text-white font-bold">{(currentPage - 1) * rowsPerPage + 1}</span> to <span className="text-white font-bold">{Math.min(currentPage * rowsPerPage, filteredLogs.length)}</span> of <span className="text-white font-bold">{filteredLogs.length}</span> events
                </div>
                <div className="flex space-x-2">
                  <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="p-2 rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-30"><ChevronLeft /></button>
                  <div className="px-4 py-2 text-sm font-bold text-white bg-slate-900 rounded border border-slate-700">Page {currentPage} of {totalPages}</div>
                  <button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} className="p-2 rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-30"><ChevronRight /></button>
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="text-center py-20 bg-slate-800/50 rounded-xl border-2 border-dashed border-slate-700">
            <UploadCloud className="mx-auto w-12 h-12 text-slate-600 mb-4" />
            <p className="text-slate-500">Awaiting Log Ingestion. Upload a file to trigger AI analysis.</p>
          </div>
        )}
      </div>
    </div>
  );
}