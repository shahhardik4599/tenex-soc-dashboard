import React from 'react';
import { AlertTriangle } from 'lucide-react';

export default function LogTable({ logs }: { logs: any[] }) {
    return (
        <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-lg overflow-hidden">
            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                    <thead className="bg-slate-900 text-slate-400">
                        <tr>
                            <th className="p-4 font-medium">Batch</th>
                            <th className="p-4 font-medium">Timestamp</th>
                            <th className="p-4 font-medium">Source IP</th>
                            <th className="p-4 font-medium">Endpoint</th>
                            <th className="p-4 font-medium">Status</th>
                            <th className="p-4 font-medium">Category & Reason</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700">
                        {logs.map((log, idx) => {
                            // Logic to determine a category "tag" for the UI
                            let category = "Normal";
                            if (log.anomaly_reason?.includes("STIX")) category = "Threat Intel";
                            if (log.anomaly_reason?.includes("Brute Force")) category = "Brute Force";
                            if (log.anomaly_reason?.includes("sensitive")) category = "Probing";
                            if (log.anomaly_reason?.includes("ML Model")) category = "ML Behavioral";

                            return (
                                <tr key={idx} className={`hover:bg-slate-700/50 transition-colors ${log.is_anomaly ? 'bg-red-900/10' : ''}`}>
                                    <td className="p-4 font-mono text-slate-500 text-xs">{log.batch_id?.substring(0, 6)}</td>
                                    <td className="p-4 whitespace-nowrap text-slate-400">{new Date(log.timestamp).toLocaleString()}</td>
                                    <td className="p-4 font-mono text-slate-300">{log.source_ip}</td>
                                    <td className="p-4 font-mono text-emerald-400 truncate max-w-[150px]">{log.http_method} {log.endpoint}</td>
                                    <td className="p-4">
                                        <span className={`px-2 py-1 rounded text-xs font-bold ${log.status_code >= 400 ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                                            {log.status_code}
                                        </span>
                                    </td>
                                    <td className="p-4">
                                        {log.is_anomaly ? (
                                            <div className="space-y-1">
                                                <div className="flex items-center gap-2">
                                                    <span className="bg-red-500 text-white text-[10px] px-1.5 py-0.5 rounded uppercase font-black">
                                                        {category}
                                                    </span>
                                                    <span className="text-red-400 font-bold text-xs">{log.confidence_score}%</span>
                                                </div>
                                                <div className="text-slate-300 text-xs italic leading-snug">{log.anomaly_reason}</div>
                                            </div>
                                        ) : <span className="text-slate-600">Verified Traffic</span>}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
}