'use client';

import React, { useState, useMemo, useEffect, useRef } from 'react';
import axios from 'axios';
import { UploadCloud, ShieldCheck, ChevronLeft, ChevronRight, History, X, LogOut, Filter } from 'lucide-react';

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

  // --- Filter State Management ---
  const [activeFilter, setFilter] = useState('all');
  const [confidenceRange, setConfidenceRange] = useState('All');
  const [severityFilter, setSeverityFilter] = useState('All');

  // --- Reference for File Upload ---
  const fileInputRef = useRef<HTMLInputElement>(null);

  // --- History State Management ---
  const [historyBatches, setHistoryBatches] = useState<any[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [isHistoryView, setIsHistoryView] = useState(false);

  // --- Pagination State ---
  const [currentPage, setCurrentPage] = useState(1);
  const rowsPerPage = 10;

  // --- API Handlers & Lifecycle ---
  useEffect(() => {
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
    setShowHistory(false);
    setCurrentPage(1);

    try {
      const authHeader = 'Basic ' + btoa(`${credentials.username}:${credentials.password}`);
      const response = await axios.get(`http://localhost:8000/batches/${selectedBatchId}`, {
        headers: { 'Authorization': authHeader }
      });

      setBatchId(response.data.batch_info.batch_id);
      setLogs(response.data.data);

      setIsHistoryView(true);
      setFilter('anomalies');
      setConfidenceRange('All'); // Reset advanced filters on load
      setSeverityFilter('All');
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

      setIsHistoryView(false);
      setFilter('all');
      setConfidenceRange('All'); // Reset advanced filters on fresh upload
      setSeverityFilter('All');

      fetchHistory(credentials);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to process logs.');
      if (err.response?.status === 401) handleLogout();
    } finally {
      setLoading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  // --- Filtering & Pagination Logic ---
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      // 1. Check Category Filter
      let categoryMatch = false;
      if (activeFilter === 'all') categoryMatch = true;
      else if (activeFilter === 'anomalies') categoryMatch = log.is_anomaly;
      else if (activeFilter === 'threat_intel') categoryMatch = log.category === 'Threat Intel';
      else if (activeFilter === 'brute_force') categoryMatch = log.category === 'Brute Force';
      else if (activeFilter === 'sensitive') categoryMatch = log.category === 'Probing';
      else if (activeFilter === 'ml') categoryMatch = log.category === 'ML Behavioral';

      // 2. Check Confidence Score Filter (Range Logic)
      let confidenceMatch = true;
      const score = log.confidence_score || 0;

      if (confidenceRange !== 'All') {
        if (confidenceRange === '0-50') confidenceMatch = score >= 0 && score < 50;
        else if (confidenceRange === '50-75') confidenceMatch = score >= 50 && score < 75;
        else if (confidenceRange === '75-90') confidenceMatch = score >= 75 && score < 90;
        else if (confidenceRange === '90-100') confidenceMatch = score >= 90 && score <= 100;
      }

      // 3. Check Severity Filter
      let severityMatch = true;
      if (severityFilter !== 'All') {
        const reason = String(log.anomaly_reason || "");
        // Matches format: 'Severity': 'High' OR "Severity": "High" OR Severity: High
        severityMatch = reason.includes(`'Severity': '${severityFilter}'`) ||
          reason.includes(`"Severity": "${severityFilter}"`) ||
          reason.includes(`Severity: ${severityFilter}`);
      }

      // The log must pass ALL active filters to be shown in the table
      return categoryMatch && confidenceMatch && severityMatch;
    });
  }, [logs, activeFilter, confidenceRange, severityFilter]);

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
            <button
              onClick={() => setShowHistory(true)}
              className="flex items-center cursor-pointer px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-white transition-colors"
            >
              <History className="w-4 h-4 mr-2" />
              History
            </button>

            <div>
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={loading}
                className={`bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2 px-6 rounded-lg shadow-lg flex items-center transition-all ${loading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
              >
                <UploadCloud className="w-5 h-5 mr-2" />
                {loading ? 'AI Engine Processing...' : 'Upload Access Log'}
              </button>
              <input
                type="file"
                accept=".log,.txt"
                onChange={handleFileUpload}
                disabled={loading}
                ref={fileInputRef}
                className="hidden"
              />
            </div>

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
            <div className="space-y-4">
              <StatsFilters
                batchId={batchId}
                activeFilter={activeFilter}
                setFilter={(f) => { setFilter(f); setCurrentPage(1); }}
                totalLogs={logs.length}
                isHistoryView={isHistoryView}
              />

              {/* --- NEW ADVANCED FILTERS BAR --- */}
              <div className="flex flex-wrap items-center gap-6 bg-slate-800 p-4 rounded-xl border border-slate-700 shadow-md">
                <div className="flex items-center text-emerald-500">
                  <Filter className="w-4 h-4 mr-2" />
                  <span className="text-sm font-bold uppercase tracking-wider">Advanced Filters</span>
                </div>

                {/* Confidence Range Filter */}
                <div className="flex items-center space-x-3">
                  <label className="text-sm font-medium text-slate-400">Confidence Range:</label>
                  <select
                    value={confidenceRange}
                    onChange={(e) => { setConfidenceRange(e.target.value); setCurrentPage(1); }}
                    className="bg-slate-900 border border-slate-600 text-white text-sm rounded-lg focus:ring-emerald-500 focus:border-emerald-500 block p-2 cursor-pointer outline-none"
                  >
                    <option value="All">All Scores</option>
                    <option value="0-50">Low (0% - 49%)</option>
                    <option value="50-75">Medium (50% - 74%)</option>
                    <option value="75-90">High (75% - 89%)</option>
                    <option value="90-100">Critical (90% - 100%)</option>
                  </select>
                </div>

                {/* Severity Filter */}
                <div className="flex items-center space-x-3">
                  <label className="text-sm font-medium text-slate-400">AI Severity:</label>
                  <select
                    value={severityFilter}
                    onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }}
                    className="bg-slate-900 border border-slate-600 text-white text-sm rounded-lg focus:ring-emerald-500 focus:border-emerald-500 block p-2 cursor-pointer outline-none"
                  >
                    <option value="All">All Severities</option>
                    <option value="Critical">Critical Only</option>
                    <option value="High">High Only</option>
                    <option value="Medium">Medium Only</option>
                    <option value="Low">Low Only</option>
                  </select>
                </div>
              </div>
            </div>

            {/* 3. Paginated Data Table */}
            <div className="space-y-4">
              <LogTable logs={paginatedLogs} />

              {/* Pagination Controls */}
              <div className="flex justify-between items-center bg-slate-800 p-4 rounded-xl border border-slate-700 shadow-md">
                <div className="text-sm text-slate-400">
                  Showing <span className="text-white font-bold">{filteredLogs.length === 0 ? 0 : (currentPage - 1) * rowsPerPage + 1}</span> to <span className="text-white font-bold">{Math.min(currentPage * rowsPerPage, filteredLogs.length)}</span> of <span className="text-white font-bold">{filteredLogs.length}</span> events
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
                    disabled={currentPage === totalPages || totalPages === 0}
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
          /* Empty State */
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