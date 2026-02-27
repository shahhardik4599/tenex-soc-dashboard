import React from 'react';

interface StatsFiltersProps {
    batchId: string;
    activeFilter: string;
    setFilter: (filter: string) => void;
    totalLogs: number;
}

export default function StatsFilters({ batchId, activeFilter, setFilter, totalLogs }: StatsFiltersProps) {
    const filterOptions = [
        { id: 'all', label: 'All Traffic' },
        { id: 'anomalies', label: 'Anomalies' },
        { id: 'brute_force', label: 'Brute Force' },
        { id: 'sensitive', label: 'Sensitive Probing' },
        { id: 'ml', label: 'ML Behavioral' },
    ];

    return (
        <div className="space-y-4">
            <div className="flex justify-between items-center">
                <div className="flex items-center space-x-2">
                    <span className="text-slate-400 text-sm">Active Batch:</span>
                    <span className="bg-emerald-900/30 text-emerald-400 px-3 py-1 rounded text-xs font-mono border border-emerald-500/30">
                        {batchId || 'No active session'}
                    </span>
                </div>
                <span className="bg-slate-700 text-slate-300 py-1 px-3 rounded-full text-sm">{totalLogs} Total Events</span>
            </div>

            <div className="flex gap-2 overflow-x-auto pb-2">
                {filterOptions.map((opt) => (
                    <button
                        key={opt.id}
                        onClick={() => setFilter(opt.id)}
                        className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all whitespace-nowrap border ${activeFilter === opt.id
                                ? 'bg-emerald-600 border-emerald-500 text-white shadow-lg shadow-emerald-900/20'
                                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                            }`}
                    >
                        {opt.label}
                    </button>
                ))}
            </div>
        </div>
    );
}