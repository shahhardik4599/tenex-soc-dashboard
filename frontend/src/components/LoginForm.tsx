import React, { useState } from 'react';
import axios from 'axios';
import { Lock } from 'lucide-react';

export default function LoginForm({ onLoginSuccess, onToggleSignup }: any) {
    const [creds, setCreds] = useState({ username: '', password: '' });
    const [error, setError] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const authHeader = 'Basic ' + btoa(`${creds.username}:${creds.password}`);
            await axios.get('http://localhost:8000/', {
                headers: { 'Authorization': authHeader }
            });
            onLoginSuccess(creds);
        } catch (err) {
            setError('Invalid username or password.');
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-4">
            {error && <div className="text-red-400 text-sm bg-red-900/20 p-2 rounded border border-red-500/50">{error}</div>}
            <input
                type="text" placeholder="Username"
                className="w-full bg-slate-900 border border-slate-700 text-white rounded p-3 outline-none focus:border-emerald-500"
                onChange={(e) => setCreds({ ...creds, username: e.target.value })} required
            />
            <input
                type="password" placeholder="Password"
                className="w-full bg-slate-900 border border-slate-700 text-white rounded p-3 outline-none focus:border-emerald-500"
                onChange={(e) => setCreds({ ...creds, password: e.target.value })} required
            />
            <button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded transition-all flex justify-center items-center">
                <Lock className="mr-2 w-5 h-5" /> Secure Login
            </button>
            <button type="button" onClick={onToggleSignup} className="w-full text-slate-400 text-sm hover:text-white transition-colors">
                Need an account? Sign Up
            </button>
        </form>
    );
}