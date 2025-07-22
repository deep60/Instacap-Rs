# 📊 Packet Analyzer Frontend

This is the **React-based dashboard** for the `packet-analyzer` system. It provides real-time visibility into network activity, anomalies, threats, and performance metrics collected from the backend services.

---

## 🚀 Features

- 📡 Live packet statistics (protocol distribution, volume)
- ⚠️ Real-time alerts from anomaly/threat detection engine
- 📈 Visual performance monitoring (latency, jitter, throughput)
- 🧠 Communicates with backend (Rust & Python services)
- 🧰 Built with `React`, `TailwindCSS`, `Recharts`, and `lucide-react`

---
#### `npm start`

#### `npm test`

#### `npm run build`

#### `npm run eject`

**Note: this is a one-way operation. Once you `eject`, you can't go back!**

If you aren't satisfied with the build tool and configuration choices, you can `eject` at any time. This command will remove the single build dependency from your project.

Instead, it will copy all the configuration files and the transitive dependencies (webpack, Babel, ESLint, etc) right into your project so you have full control over them. All of the commands except `eject` will still work, but they will point to the copied scripts so you can tweak them. At this point you're on your own.

You don't have to ever use `eject`. The curated feature set is suitable for small and middle deployments, and you shouldn't feel obligated to use this feature. However we understand that this tool wouldn't be useful if you couldn't customize it when you are ready for it.

#### `npm run build` fails to minify


```plaintext
Instacap-Rs-frontend/
├── public/
│   ├── index.html
│   ├── manifest.json
│   └── favicon.ico
├── src/
│   ├── components/
│   │   ├── Dashboard/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── StatsGrid.jsx
│   │   │   ├── TrafficChart.jsx
│   │   │   └── AlertsPanel.jsx
│   │   ├── PacketAnalysis/
│   │   │   ├── PacketTable.jsx
│   │   │   ├── PacketFilters.jsx
│   │   │   └── PacketDetails.jsx
│   │   ├── ThreatDetection/
│   │   │   ├── ThreatDashboard.jsx
│   │   │   ├── ThreatList.jsx
│   │   │   └── ThreatDetails.jsx
│   │   ├── Performance/
│   │   │   ├── PerformanceMetrics.jsx
│   │   │   ├── LatencyChart.jsx
│   │   │   └── BandwidthChart.jsx
│   │   ├── Protocol/
│   │   │   ├── ProtocolAnalysis.jsx
│   │   │   ├── ProtocolChart.jsx
│   │   │   └── ProtocolDetails.jsx
│   │   ├── Common/
│   │   │   ├── Header.jsx
│   │   │   ├── Navigation.jsx
│   │   │   ├── StatCard.jsx
│   │   │   ├── AlertItem.jsx
│   │   │   └── LoadingSpinner.jsx
│   │   └── Layout/
│   │       ├── MainLayout.jsx
│   │       └── Sidebar.jsx
│   ├── services/
│   │   ├── api.js
│   │   ├── websocket.js
│   │   ├── packetService.js
│   │   ├── threatService.js
│   │   └── analyticsService.js
│   ├── hooks/
│   │   ├── useWebSocket.js
│   │   ├── usePacketData.js
│   │   ├── useThreatDetection.js
│   │   └── useRealTimeUpdates.js
│   ├── utils/
│   │   ├── constants.js
│   │   ├── helpers.js
│   │   ├── formatters.js
│   │   └── validators.js
│   ├── styles/
│   │   ├── globals.css
│   │   ├── components.css
│   │   └── tailwind.css
│   ├── App.jsx
│   ├── index.js
│   └── reportWebVitals.js
├── package.json
├── tailwind.config.js
├── postcss.config.js
├── .env.example
├── .gitignore
└── README.md