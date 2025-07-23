import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import MainLayout from './components/Layout/MainLayout';
import Dashboard from './components/Dashboard/Dashboard';
import PacketAnalysis from './components/PacketAnalysis/PacketTable';
import ThreatDetection from './components/ThreatDetection/ThreatDashboard';
import PerformanceMetrics from './components/Performance/PerformanceMetrics';
import ProtocolAnalysis from './components/Protocol/ProtocolAnalysis';
import './styles/globals.css';

function App() {
  return (
    <Router>
      <MainLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/packets" element={<PacketAnalysis />} />
          <Route path="/threats" element={<ThreatDetection />} />
          <Route path="/performance" element={<PerformanceMetrics />} />
          <Route path="/protocols" element={<ProtocolAnalysis />} />
        </Routes>
      </MainLayout>
    </Router>
  );
}

export default App;
