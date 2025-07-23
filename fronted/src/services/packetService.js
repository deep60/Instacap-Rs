import { apiService } from './api';

class PacketService {
  async getPackets(filters = {}) {
    // Simulate API call with mock data for demo
    return new Promise((resolve) => {
      setTimeout(() => {
        const mockPackets = this.generateMockPackets(filters.pageSize || 50);
        resolve({
          packets: mockPackets,
          total: 1000,
          page: filters.page || 1,
          pageSize: filters.pageSize || 50
        });
      }, 500);
    });
  }

  async getPacketDetails(packetId) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          id: packetId,
          timestamp: new Date().toISOString(),
          srcIp: '192.168.1.100',
          dstIp: '8.8.8.8',
          srcPort: 54321,
          dstPort: 80,
          protocol: 'HTTP',
          size: 1024,
          payload: 'GET / HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0...',
          headers: {
            'Content-Type': 'text/html',
            'Content-Length': '1024'
          }
        });
      }, 300);
    });
  }

  async startCapture(interfaceName = 'eth0', filters = {}) {
    return apiService.post('/packets/capture/start', {
      interface: interfaceName,
      filters: filters
    });
  }

  async stopCapture() {
    return apiService.post('/packets/capture/stop');
  }

  async getCaptureStatus() {
    return apiService.get('/packets/capture/status');
  }

  async exportPackets(format = 'pcap', filters = {}) {
    return apiService.post('/packets/export', {
      format: format,
      filters: filters
    });
  }

  generateMockPackets(count) {
    const protocols = ['HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS', 'FTP', 'SSH'];
    const ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '8.8.8.8', '1.1.1.1'];
    const packets = [];

    for (let i = 0; i < count; i++) {
      const timestamp = new Date(Date.now() - Math.random() * 3600000);
      packets.push({
        id: `packet_${i + 1}`,
        timestamp: timestamp.toISOString(),
        srcIp: ips[Math.floor(Math.random() * ips.length)],
        dstIp: ips[Math.floor(Math.random() * ips.length)],
        srcPort: Math.floor(Math.random() * 65535),
        dstPort: Math.floor(Math.random() * 65535),
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        size: Math.floor(Math.random() * 1500) + 64,
        flags: ['SYN', 'ACK', 'PSH', 'FIN'][Math.floor(Math.random() * 4)]
      });
    }

    return packets.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }
}

export const packetService = new PacketService();
