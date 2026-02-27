import React, { useState } from 'react';
import LoginForm from './LoginForm';
import SignupForm from './SignupForm';
import { ShieldCheck } from 'lucide-react';

interface AuthProps {
    onLoginSuccess: (creds: any) => void;
}

export default function AuthContainer({ onLoginSuccess }: AuthProps) {
    const [isSignup, setIsSignup] = useState(false);

    return (
        <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4">
            <div className="bg-slate-800 p-8 rounded-xl shadow-2xl max-w-md w-full border border-slate-700">
                <div className="flex items-center justify-center mb-8">
                    <ShieldCheck className="text-emerald-500 w-12 h-12 mr-3" />
                    <h1 className="text-2xl font-bold text-white">TENEX.ai MDR</h1>
                </div>

                {isSignup ? (
                    <SignupForm onBackToLogin={() => setIsSignup(false)} />
                ) : (
                    <LoginForm
                        onLoginSuccess={onLoginSuccess}
                        onToggleSignup={() => setIsSignup(true)}
                    />
                )}
            </div>
        </div>
    );
}