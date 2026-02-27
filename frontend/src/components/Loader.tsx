import { ShieldCheck } from 'lucide-react';

export default function Loader() {
    return (
        <div className="flex flex-col items-center justify-center py-20 space-y-4">
            <div className="relative">
                <div className="absolute inset-0 rounded-full border-4 border-emerald-500/20 animate-pulse"></div>
                <div className="w-16 h-16 rounded-full border-t-4 border-emerald-500 animate-spin"></div>
                <ShieldCheck className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-emerald-500 w-8 h-8" />
            </div>
            <div className="text-center">
                <h3 className="text-white font-bold text-lg animate-pulse">AI Engine Analyzing...</h3>
                <p className="text-slate-500 text-sm">Triangulating threats & applying ML heuristics</p>
            </div>
        </div>
    );
}