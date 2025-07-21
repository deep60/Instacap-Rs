import React from "react";
import { Network, Settings } from 'lucide-react';

const Header = () => {
    return (
        <header className="bg-slate-800 text-white p-4 shadow-lg">
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                    <Network className="w-8 h-8 text-blue-400" />
                        <h1 className="text-2xl font-bold">
                            Packet Analyzer
                        </h1>
                </div>
                <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-2 bg-screen-600 px-3 py-1 rounded-full">
                        <div className="w-2 h-2 bg-green-300 rounded-full animate-pulse"></div>
                        <span className="text-sm">Live</span>
                    </div>
                    <button className="p-2 hover:bg-slate-700 rounded-lg">
                        <Settings className="w-5 h-5" />
                    </button>
                </div>
            </div>
        </header>
    );
};

export default Header;