import React, { useMemo } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function ThreatChart({ logs }: { logs: any[] }) {
    const chartData = useMemo(() => {
        if (!logs || logs.length === 0) return [];

        const grouped = logs.reduce((acc: any, log: any) => {
            const time = new Date(log.timestamp);
            // Round to nearest minute for grouping
            const timeKey = time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            if (!acc[timeKey]) {
                acc[timeKey] = { time: timeKey, timestamp: time.getTime(), total: 0, bruteForce: 0, probing: 0, ml: 0, intel: 0 };
            }

            acc[timeKey].total += 1;
            if (log.category === "Brute Force") acc[timeKey].bruteForce += 1;
            if (log.category === "Probing") acc[timeKey].probing += 1;
            if (log.category === "ML Behavioral") acc[timeKey].ml += 1;
            if (log.category === "Threat Intel") acc[timeKey].intel += 1;
            return acc;
        }, {});

        let sortedData = Object.values(grouped).sort((a: any, b: any) => a.timestamp - b.timestamp);

        // TRICK: If we only have 1 data point, add a "0" value before and after 
        // to force the AreaChart to draw a triangle instead of a single dot.
        if (sortedData.length === 1) {
            const singlePoint = sortedData[0] as any;
            const before = { ...singlePoint, time: " ", timestamp: singlePoint.timestamp - 60000, total: 0, bruteForce: 0, probing: 0, ml: 0, intel: 0 };
            const after = { ...singlePoint, time: "  ", timestamp: singlePoint.timestamp + 60000, total: 0, bruteForce: 0, probing: 0, ml: 0, intel: 0 };
            sortedData = [before, singlePoint, after];
        }

        return sortedData;
    }, [logs]);

    if (logs.length === 0) return null;

    return (
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg">
            <h2 className="text-lg font-semibold text-white mb-4">Live Threat Timeline</h2>
            <div className="h-72 w-full">
                <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                        <defs>
                            <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#10b981" stopOpacity={0.2} />
                                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                        <XAxis dataKey="time" stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                        <YAxis stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />

                        {/* FIX: stackId is removed so they don't stack to match ML point.
                            fillOpacity={0.6} added so you can see them overlapping cleanly.
                        */}
                        <Area type="monotone" dataKey="total" stroke="#10b981" fillOpacity={1} fill="url(#colorTotal)" name="Total Traffic" dot={{ r: 4, fill: '#10b981' }} />
                        <Area type="monotone" dataKey="intel" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} name="Threat Intel" dot={{ r: 3 }} />
                        <Area type="monotone" dataKey="ml" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.6} name="ML Behavioral" dot={{ r: 3 }} />
                        <Area type="monotone" dataKey="bruteForce" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.6} name="Brute Force" dot={{ r: 3 }} />
                        <Area type="monotone" dataKey="probing" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.6} name="Probing" dot={{ r: 3 }} />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}