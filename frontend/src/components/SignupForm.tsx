import React, { useState } from 'react';
import axios from 'axios';
import { UserPlus } from 'lucide-react';

export default function SignupForm({ onBackToLogin }: any) {
    const [creds, setCreds] = useState({ username: '', password: '' });
    const [error, setError] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            await axios.post('http://localhost:8000/signup', creds);
            alert("Account created successfully!");
            onBackToLogin();
        } catch (err: any) {
            setError(err.response?.data?.detail || 'Signup failed');
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-4">
            {error && <div className="text-red-400 text-sm bg-red-900/20 p-2 rounded border border-red-500/50">{error}</div>}
            <input
                type="text" placeholder="Choose Username"
                className="w-full bg-slate-900 border border-slate-700 text-white rounded p-3 outline-none focus:border-emerald-500"
                onChange={(e) => setCreds({ ...creds, username: e.target.value })} required
            />
            <input
                type="password" placeholder="Choose Password"
                className="w-full bg-slate-900 border border-slate-700 text-white rounded p-3 outline-none focus:border-emerald-500"
                onChange={(e) => setCreds({ ...creds, password: e.target.value })} required
            />
            <button type="submit" className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded transition-all flex justify-center items-center">
                <UserPlus className="mr-2 w-5 h-5" /> Create Account
            </button>
            <button type="button" onClick={onBackToLogin} className="w-full text-slate-400 text-sm hover:text-white transition-colors">
                Already have an account? Login
            </button>
        </form>
    );
}