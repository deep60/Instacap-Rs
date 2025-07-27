import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
// import './styles/globals.css';
// import './styles/components.css';
// import './styles/tailwind.css';

// Layout Components
import MainLayout from './components/Layout/MainLayout';
import Header from './components/Common/Header';

// Dashboard Components
import Dashboard from './components/Dashboard/Dashboard';

// Packet Analysis Components
import PacketTable from './components/PacketAnalysis/PacketTable';
import PacketFilters from './components/PacketAnalysis/PacketFilters';
import PacketDetails from './components/PacketAnalysis/PacketDetails';

// Threat Detection Components
import ThreatDashboard from './components/ThreatDetection/ThreatDashboard';
import ThreatList from './components/ThreatDetection/ThreatList';
import ThreatDetails from './components/ThreatDetection/ThreatDetails';

// Performance Components
import PerformanceMetrics from './components/Performance/PerformanceMetrics';

// Protocol Components
import ProtocolAnalysis from './components/Protocol/ProtocolAnalysis';

// Services
import { initializeWebSocket, closeWebSocket } from './services/webSocket';
import { setApiBaseUrl } from './services/api';

// Hooks
import useWebSocket from './hooks/useWebSocket';
import useRealTimeUpdates from './hooks/useRealTimeUpdates';

// Utils
import { WEBSOCKET_EVENTS } from './utils/constants';

function App() {
  // Application state
  const [isConnected, setIsConnected] = useState(false);
  const [currentView, setCurrentView] = useState('dashboard');
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [filters, setFilters] = useState({
    protocol: '',
    sourceIp: '',
    destinationIp: '',
    port: '',
    timeRange: '1h'
  });
  const [alerts, setAlerts] = useState([]);
  const [systemStatus, setSystemStatus] = useState({
    captureStatus: 'stopped',
    analysisStatus: 'idle',
    mlModelsStatus: 'ready',
    connectionStatus: 'disconnected'
  });

  // WebSocket connection for real-time updates
  const { 
    connectionStatus, 
    lastMessage, 
    sendMessage 
  } = useWebSocket(process.env.REACT_APP_WEBSOCKET_URL || 'ws://localhost:8080');

  // Real-time data updates
  const {
    packetData,
    threatData,
    performanceMetrics,
    protocolStats
  } = useRealTimeUpdates(lastMessage);

  // Initialize application
  useEffect(() => {
    // Set API base URL from environment
    const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:3001';
    setApiBaseUrl(apiUrl);

    // Initialize WebSocket connection
    const wsUrl = process.env.REACT_APP_WEBSOCKET_URL || 'ws://localhost:8080';
    initializeWebSocket(wsUrl, {
      onOpen: () => {
        setIsConnected(true);
        setSystemStatus(prev => ({ ...prev, connectionStatus: 'connected' }));
      },
      onClose: () => {
        setIsConnected(false);
        setSystemStatus(prev => ({ ...prev, connectionStatus: 'disconnected' }));
      },
      onError: (error) => {
        console.error('WebSocket error:', error);
        setSystemStatus(prev => ({ ...prev, connectionStatus: 'error' }));
      }
    });

    // Cleanup on unmount
    return () => {
      closeWebSocket();
    };
  }, []);

  // Handle WebSocket messages
  useEffect(() => {
    if (lastMessage) {
      try {
        const message = JSON.parse(lastMessage.data);
        handleWebSocketMessage(message);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    }
  }, [lastMessage]);

  // WebSocket message handler
  const handleWebSocketMessage = (message) => {
    switch (message.type) {
      case WEBSOCKET_EVENTS.PACKET_CAPTURED:
        // Handle new packet data
        break;
      case WEBSOCKET_EVENTS.THREAT_DETECTED:
        setAlerts(prev => [message.data, ...prev.slice(0, 99)]); // Keep last 100 alerts
        break;
      case WEBSOCKET_EVENTS.SYSTEM_STATUS:
        setSystemStatus(prev => ({ ...prev, ...message.data }));
        break;
      case WEBSOCKET_EVENTS.PERFORMANCE_UPDATE:
        // Handle performance metrics update
        break;
      default:
        console.log('Unknown message type:', message.type);
    }
  };

  // Navigation handlers
  const handleViewChange = (view) => {
    // Map sidebar view IDs to internal view names for backward compatibility
    const viewMap = {
      'packets': 'packet-analysis',
      'threats': 'threat-detection',
      'protocols': 'protocol-analysis'
    };
    
    const mappedView = viewMap[view] || view;
    setCurrentView(mappedView);
    setSelectedPacket(null);
    setSelectedThreat(null);
  };

  const handlePacketSelect = (packet) => {
    setSelectedPacket(packet);
    setCurrentView('packet-details');
  };

  const handleThreatSelect = (threat) => {
    setSelectedThreat(threat);
    setCurrentView('threat-details');
  };

  // Filter handlers
  const handleFiltersChange = (newFilters) => {
    setFilters({ ...filters, ...newFilters });
  };

  const handleClearFilters = () => {
    setFilters({
      protocol: '',
      sourceIp: '',
      destinationIp: '',
      port: '',
      timeRange: '1h'
    });
  };

  // System control handlers
  const handleStartCapture = () => {
    sendMessage({
      type: 'START_CAPTURE',
      filters: filters
    });
  };

  const handleStopCapture = () => {
    sendMessage({
      type: 'STOP_CAPTURE'
    });
  };

  const handleExportData = (format = 'pcap') => {
    sendMessage({
      type: 'EXPORT_DATA',
      format: format,
      filters: filters
    });
  };

  // Render packet analysis view
  const renderPacketAnalysis = () => (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
        <PacketFilters 
          filters={filters}
          onFiltersChange={handleFiltersChange}
          onClearFilters={handleClearFilters}
          onStartCapture={handleStartCapture}
          onStopCapture={handleStopCapture}
          captureStatus={systemStatus.captureStatus}
        />
      </div>
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm">
        <PacketTable 
          packets={packetData}
          onPacketSelect={handlePacketSelect}
          filters={filters}
          isLoading={!isConnected}
        />
      </div>
    </div>
  );


  return (
    <Router>
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <Header 
          systemStatus={systemStatus}
          connectionStatus={connectionStatus}
          alertsCount={alerts.length}
          onExportData={handleExportData}
        />
        
        <MainLayout 
          currentView={currentView} 
          onViewChange={handleViewChange}
        >
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={
              <Dashboard 
                packetData={packetData}
                threatData={threatData}
                performanceMetrics={performanceMetrics}
                protocolStats={protocolStats}
                alerts={alerts}
                systemStatus={systemStatus}
                onViewChange={handleViewChange}
              />
            } />
            <Route path="/packets" element={renderPacketAnalysis()} />
            <Route path="/packets/:id" element={
              <PacketDetails 
                packet={selectedPacket}
                onBack={() => handleViewChange('packet-analysis')}
              />
            } />
            <Route path="/threats" element={
              <ThreatDashboard 
                threats={threatData}
                alerts={alerts}
                onThreatSelect={handleThreatSelect}
              />
            } />
            <Route path="/threats/:id" element={
              <ThreatDetails 
                threat={selectedThreat}
                onBack={() => handleViewChange('threat-detection')}
              />
            } />
            <Route path="/performance" element={
              <PerformanceMetrics 
                metrics={performanceMetrics}
                isRealTime={isConnected}
                timeRange={filters.timeRange}
              />
            } />
            <Route path="/protocols" element={
              <ProtocolAnalysis 
                protocolStats={protocolStats}
                timeRange={filters.timeRange}
                onProtocolSelect={(protocol) => {
                  setFilters(prev => ({ ...prev, protocol }));
                  handleViewChange('packet-analysis');
                }}
              />
            } />
          </Routes>
        </MainLayout>
      </div>
    </Router>
  );
}

export default App;