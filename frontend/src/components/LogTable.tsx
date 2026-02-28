import React from 'react';
import { AlertTriangle } from 'lucide-react';

export default function LogTable({ logs }: { logs: any[] }) {

    // --- NEW HELPER FUNCTION ---
    const formatAIReason = (text: string) => {
        if (!text) return text;

        let cleanText = text;

        // 1. If the AI returned a stringified dictionary (e.g., {'Severity': 'High', ...})
        // This strips the brackets/quotes and forces line breaks
        if (cleanText.includes("{'Severity'") || cleanText.includes('{"Severity"')) {
            cleanText = cleanText
                .replace(/\{['"]Severity['"]:\s*['"]?/i, 'Severity: ')
                .replace(/['"]?,\s*['"]Risk['"]:\s*['"]?/i, '\nRisk: ')
                .replace(/['"]?,\s*['"]Action['"]:\s*['"]?/i, '\nAction: ')
                .replace(/['"]?\}$/g, ''); // Removes the trailing quote and bracket
        }
        // 2. Fallback: If it returned standard period-separated sentences
        else {
            cleanText = cleanText
                .replace(/\.\s*Risk:/g, '.\nRisk:')
                .replace(/\.\s*Action:/g, '.\nAction:');
        }

        return cleanText;
    };

    return (
        <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-lg overflow-hidden">
            <table className="w-full text-left text-sm">
                <thead className="bg-slate-900 text-slate-400">
                    <tr>
                        <th className="p-4 font-medium">Timestamp</th>
                        <th className="p-4 font-medium">Source IP</th>
                        <th className="p-4 font-medium">Endpoint</th>
                        <th className="p-4 font-medium">Status</th>
                        <th className="p-4 font-medium">Category & Reason</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                    {logs.map((log, idx) => (
                        <tr key={idx} className={`hover:bg-slate-700/50 transition-colors ${log.is_anomaly ? 'bg-red-900/10' : ''}`}>
                            <td className="p-4 text-slate-400">{new Date(log.timestamp).toLocaleString()}</td>
                            <td className="p-4 font-mono text-slate-300">{log.source_ip}</td>
                            <td className="p-4 font-mono text-emerald-400 truncate max-w-[200px]">{log.http_method} {log.endpoint}</td>
                            <td className="p-4">
                                <span className={`px-2 py-1 rounded text-xs font-bold ${log.status_code >= 400 ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                                    {log.status_code}
                                </span>
                            </td>
                            <td className="p-4">
                                {log.is_anomaly ? (
                                    <div className="space-y-1">
                                        <div className="flex items-center gap-2">
                                            <span className="bg-red-600 text-white text-[10px] px-2 py-0.5 rounded font-black uppercase">
                                                {log.category}
                                            </span>
                                            <span className="text-red-400 font-bold text-xs">{log.confidence_score}%</span>
                                        </div>
                                        {/* --- UPDATED: Added whitespace-pre-line and the helper function --- */}
                                        <div className="text-slate-300 text-xs italic whitespace-pre-line mt-1">
                                            {formatAIReason(log.anomaly_reason)}
                                        </div>
                                    </div>
                                ) : <span className="text-slate-600">Verified Traffic</span>}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}