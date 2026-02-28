'use client';

import React, { useState, useMemo, useEffect, useRef } from 'react';
import axios from 'axios';
import { UploadCloud, ShieldCheck, ChevronLeft, ChevronRight, History, X, LogOut } from 'lucide-react';

// Component Imports
import AuthContainer from '@/components/AuthContainer';
import StatsFilters from '@/components/StatsFilters';
import LogTable from '@/components/LogTable';
import CyberLoader from '@/components/Loader';
import ThreatChart from '@/components/ThreatChart';

export default function SOCDashboard() {
  // --- Core State Management ---
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [logs, setLogs] = useState<any[]>([]);
  const [batchId, setBatchId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeFilter, setFilter] = useState('all');

  // --- Reference for File Upload ---
  const fileInputRef = useRef<HTMLInputElement>(null);

  // --- History State Management ---
  const [historyBatches, setHistoryBatches] = useState<any[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [isHistoryView, setIsHistoryView] = useState(false); // Tracks if viewing historical data

  // --- Pagination State ---
  const [currentPage, setCurrentPage] = useState(1);
  const rowsPerPage = 10;

  // --- API Handlers & Lifecycle ---
  useEffect(() => {
    // Check session storage for saved credentials when the page loads
    const saved = sessionStorage.getItem('tenex_credentials');
    if (saved) {
      const parsedCreds = JSON.parse(saved);
      setCredentials(parsedCreds);
      setIsLoggedIn(true);
      fetchHistory(parsedCreds);
    }
  }, []);

  const fetchHistory = async (creds: any) => {
    try {
      const authHeader = 'Basic ' + btoa(`${creds.username}:${creds.password}`);
      const response = await axios.get('http://localhost:8000/batches', {
        headers: { 'Authorization': authHeader }
      });
      setHistoryBatches(response.data.batches);
    } catch (err) {
      console.error("Failed to fetch history", err);
    }
  };

  const handleLoginSuccess = (creds: any) => {
    setCredentials(creds);
    setIsLoggedIn(true);
    // Save to session storage: survives refresh, dies when tab closes
    sessionStorage.setItem('tenex_credentials', JSON.stringify(creds));
    fetchHistory(creds);
  };

  const handleLogout = () => {
    setCredentials({ username: '', password: '' });
    setIsLoggedIn(false);
    setLogs([]);
    setBatchId('');
    setShowHistory(false);
    sessionStorage.removeItem('tenex_credentials');
  };

  const loadHistoricalBatch = async (selectedBatchId: string) => {
    setLoading(true);
    setError('');
    setShowHistory(false); // Close the sidebar
    setCurrentPage(1);     // Reset pagination

    try {
      const authHeader = 'Basic ' + btoa(`${credentials.username}:${credentials.password}`);
      const response = await axios.get(`http://localhost:8000/batches/${selectedBatchId}`, {
        headers: { 'Authorization': authHeader }
      });

      setBatchId(response.data.batch_info.batch_id);
      setLogs(response.data.data);

      // Update view state for history
      setIsHistoryView(true);
      setFilter('anomalies'); // Default to anomalies since safe traffic isn't saved
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load historical batch.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;

    setLoading(true);
    setError('');
    setCurrentPage(1);
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

      // Update view state for fresh upload
      setIsHistoryView(false);
      setFilter('all'); // Default to all traffic for a new upload

      // Refresh the history list so the new upload appears in the sidebar!
      fetchHistory(credentials);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to process logs.');
      if (err.response?.status === 401) handleLogout(); // Force logout on auth failure
    } finally {
      setLoading(false);
      // Reset the input value so the same file can be uploaded again if needed
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  // --- Filtering & Pagination Logic ---
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      if (activeFilter === 'all') return true;
      if (activeFilter === 'anomalies') return log.is_anomaly;
      if (activeFilter === 'threat_intel') return log.category === 'Threat Intel';
      if (activeFilter === 'brute_force') return log.category === 'Brute Force';
      if (activeFilter === 'sensitive') return log.category === 'Probing';
      if (activeFilter === 'ml') return log.category === 'ML Behavioral';
      return true;
    });
  }, [logs, activeFilter]);

  const totalPages = Math.ceil(filteredLogs.length / rowsPerPage) || 1;
  const paginatedLogs = filteredLogs.slice(
    (currentPage - 1) * rowsPerPage,
    currentPage * rowsPerPage
  );

  // --- Auth Guard ---
  if (!isLoggedIn) {
    return <AuthContainer onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-300 p-8 font-sans relative">

      {/* --- HISTORY SIDEBAR OVERLAY --- */}
      {showHistory && (
        <div className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" onClick={() => setShowHistory(false)}></div>
      )}
      <div className={`fixed inset-y-0 right-0 w-96 bg-slate-800 border-l border-slate-700 shadow-2xl p-6 transform transition-transform duration-300 z-50 overflow-y-auto ${showHistory ? 'translate-x-0' : 'translate-x-full'}`}>
        <div className="flex justify-between items-center mb-8 border-b border-slate-700 pb-4">
          <h2 className="text-xl font-bold text-white flex items-center">
            <History className="w-5 h-5 mr-3 text-emerald-500" />
            Upload History
          </h2>
          <button onClick={() => setShowHistory(false)} className="text-slate-400 hover:text-white transition-colors">
            <X className="w-6 h-6" />
          </button>
        </div>

        <div className="space-y-4">
          {historyBatches.length === 0 ? (
            <div className="text-center py-10">
              <History className="w-10 h-10 mx-auto text-slate-600 mb-3" />
              <p className="text-slate-500 text-sm">No previous batches found.</p>
            </div>
          ) : (
            historyBatches.map((batch: any) => (
              <div
                key={batch.batch_id}
                onClick={() => loadHistoricalBatch(batch.batch_id)}
                className={`bg-slate-900 p-4 rounded-xl border-2 cursor-pointer transition-all hover:-translate-y-1 hover:shadow-lg ${batch.batch_id === batchId ? 'border-emerald-500 shadow-emerald-900/20' : 'border-slate-700 hover:border-slate-500'}`}
              >
                <div className="flex justify-between items-start mb-2">
                  <p className="text-emerald-400 font-bold text-sm truncate pr-2" title={batch.filename}>
                    {batch.filename}
                  </p>
                  <span className="bg-red-900/30 text-red-400 border border-red-800 px-2 py-0.5 rounded-full text-xs font-bold whitespace-nowrap">
                    {batch.anomalies_count} Threats
                  </span>
                </div>
                <div className="text-xs text-slate-500 font-mono">
                  {new Date(batch.created_at).toLocaleString()}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
      {/* --- END SIDEBAR --- */}

      <div className="max-w-7xl mx-auto space-y-8">

        {/* Header */}
        <div className="flex justify-between items-center border-b border-slate-700 pb-4">
          <div className="flex items-center">
            <ShieldCheck className="text-emerald-500 w-8 h-8 mr-3" />
            <h1 className="text-2xl font-bold text-white">TENEX SOC Dashboard</h1>
          </div>

          <div className="flex items-center space-x-4">
            {/* 1st Button: History Toggle */}
            <button
              onClick={() => setShowHistory(true)}
              className="flex items-center cursor-pointer px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-white transition-colors"
            >
              <History className="w-4 h-4 mr-2" />
              History
            </button>

            {/* 2nd Button: Upload Button */}
            <div>
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={loading}
                className={`bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2 px-6 rounded-lg shadow-lg flex items-center transition-all ${loading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
              >
                <UploadCloud className="w-5 h-5 mr-2" />
                {loading ? 'AI Engine Processing...' : 'Upload Access Log'}
              </button>
              {/* The hidden shared file input */}
              <input
                type="file"
                accept=".log,.txt"
                onChange={handleFileUpload}
                disabled={loading}
                ref={fileInputRef}
                className="hidden"
              />
            </div>

            {/* 3rd Button: Logout (Moved to the end) */}
            <button
              onClick={handleLogout}
              className="flex items-center cursor-pointer px-4 py-2 bg-red-900/30 hover:bg-red-900/50 border border-red-800 rounded-lg text-red-400 transition-colors"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </button>
          </div>
        </div>

        {error && <div className="bg-red-900/50 border border-red-500 text-red-200 p-4 rounded-xl shadow-lg">{error}</div>}

        {loading ? (
          <CyberLoader />
        ) : logs.length > 0 ? (
          <div className="space-y-8 animate-in fade-in duration-500">
            {/* 1. Interactive Chart */}
            <ThreatChart logs={filteredLogs} />

            {/* 2. Global Filters */}
            <StatsFilters
              batchId={batchId}
              activeFilter={activeFilter}
              setFilter={(f) => { setFilter(f); setCurrentPage(1); }}
              totalLogs={logs.length}
              isHistoryView={isHistoryView}
            />

            {/* 3. Paginated Data Table */}
            <div className="space-y-4">
              <LogTable logs={paginatedLogs} />

              {/* Pagination Controls */}
              <div className="flex justify-between items-center bg-slate-800 p-4 rounded-xl border border-slate-700 shadow-md">
                <div className="text-sm text-slate-400">
                  Showing <span className="text-white font-bold">{(currentPage - 1) * rowsPerPage + 1}</span> to <span className="text-white font-bold">{Math.min(currentPage * rowsPerPage, filteredLogs.length)}</span> of <span className="text-white font-bold">{filteredLogs.length}</span> events
                </div>
                <div className="flex space-x-2">
                  <button
                    disabled={currentPage === 1}
                    onClick={() => setCurrentPage(p => p - 1)}
                    className="p-2 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-30 transition-colors"
                  >
                    <ChevronLeft className="w-5 h-5" />
                  </button>
                  <div className="px-4 py-2 text-sm font-bold text-white bg-slate-900 rounded-lg border border-slate-700 min-w-[120px] text-center">
                    Page {currentPage} of {totalPages}
                  </div>
                  <button
                    disabled={currentPage === totalPages}
                    onClick={() => setCurrentPage(p => p + 1)}
                    className="p-2 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-30 transition-colors"
                  >
                    <ChevronRight className="w-5 h-5" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* Empty State - Now Clickable! */
          <div
            onClick={() => !loading && fileInputRef.current?.click()}
            className="text-center py-32 bg-slate-800/30 rounded-2xl border-2 border-dashed border-slate-700 shadow-inner cursor-pointer hover:bg-slate-800/50 hover:border-emerald-500 transition-all group"
          >
            <UploadCloud className="mx-auto w-16 h-16 text-slate-600 mb-6 group-hover:text-emerald-500 transition-colors" />
            <h3 className="text-xl font-bold text-white mb-2 group-hover:text-emerald-400 transition-colors">No Active Batch</h3>
            <p className="text-slate-500 max-w-md mx-auto">Click here to upload a new access log to trigger the AI analysis engine, or open your History to load a previously processed file.</p>
          </div>
        )}
      </div>
    </div>
  );
}