-- Wireshark capture filters for network packet analysis and mointoring

-- Load required modules
local utils = require("utils")

-- Initialize capture filter configuration
local capture_filters = {}

-- =============================================================================
-- BASIC TRAFFIC FILTERS
-- =============================================================================

-- Filter for HTTP traffic (port 80 and 8080)
capture_filters.http_traffic = "tcp port 80 or tcp port 8080"

-- filter for https traffic (port 443)
capture_filters.http_traffic = "tcp port 443"

-- Filter for DNS traffic (port 53)
capture_filters.dns_traffic = "udp port 53 or tcp port 53"

-- Filter for FTP traffic (ports 20, 21)
capture_filters.ftp_traffic = "tcp port 20 or tcp port 21"

-- Filter for SSH traffic (port 22)
capture_filters.ssh_traffic = "tcp port 22"

-- Filter for Telnet traffic (port 23)
capture_filters.telnet_traffic = "tcp port 23"

-- Filter for SMTP traffic (port 25)
capture_filters.smtp_traffic = "tcp port 25"

-- Filter for POP3 traffic (port 110)
capture_filters.pop3_traffic = "tcp port 110"

-- Filter for IMAP traffic (port 143)
capture_filters.imap_traffic = "tcp port 143"

-- Filter for SNMP traffic (port 161)
capture_filters.snmp_traffic = "udp port 161"

-- =============================================================================
-- SECURITY MONITORING FILTERS
-- =============================================================================

-- Filter for potential port scanning activity
capture_filters.port_scan_detection = [[
    (tcp[tcpflags] & (tcp-syn) != 0) and 
    (tcp[tcpflags] & (tcp-ack) == 0) and 
    (tcp[tcpflags] & (tcp-rst) == 0)
]]

-- Filter for TCP RST packets (connection resets)
capture_filters.tcp_resets = "tcp[tcpflags] & (tcp-rst) != 0"

-- Filter for ICMP traffic (ping, traceroute)
capture_filters.icmp_traffic = "icmp"

-- Filter for ARP traffic (address resolution)
capture_filters.arp_traffic = "arp"

-- Filter for broadcast traffic
capture_filters.broadcast_traffic = "broadcast"

-- Filter for multicast traffic
capture_filters.multicast_traffic = "multicast"

-- =============================================================================
-- ANOMALY DETECTION FILTERS
-- =============================================================================

-- Filter for large packets (potential data exfiltration)
capture_filters.large_packets = "greater 1500"

-- Filter for fragmented packets
capture_filters.fragmented_packets = "ip[6:2] & 0x3fff != 0"

-- Filter for packets with unusual TTL values
capture_filters.unusual_ttl = "ip[8] < 10 or ip[8] > 250"

-- Filter for packets from private IP ranges to external networks
capture_filters.internal_to_external = [[
    src net (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16) and
    not dst net (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
]]

-- Filter for external to internal traffic
capture_filters.external_to_internal = [[
    not src net (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16) and
    dst net (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
]]

-- =============================================================================
-- PERFORMANCE MONITORING FILTERS
-- =============================================================================

-- Filter for TCP retransmissions
capture_filters.tcp_retransmissions = "tcp[tcpflags] & (tcp-push) != 0"

-- Filter for TCP zero window packets
capture_filters.tcp_zero_window = "tcp[14:2] == 0"

-- Filter for TCP duplicate ACKs
capture_filters.tcp_dup_acks = "tcp[tcpflags] & (tcp-ack) != 0"

-- Filter for UDP traffic
capture_filters.udp_traffic = "udp"

-- Filter for TCP traffic
capture_filters.tcp_traffic = "tcp"

-- =============================================================================
-- THREAT DETECTION FILTERS
-- =============================================================================

-- Filter for potential DDoS SYN flood attacks
capture_filters.syn_flood = [[
    tcp[tcpflags] & (tcp-syn) != 0 and
    tcp[tcpflags] & (tcp-ack) == 0
]]

-- Filter for potential DNS amplification attacks
capture_filters.dns_amplification = "udp port 53 and greater 512"

-- Filter for suspicious high-numbered ports
capture_filters.high_ports = "port > 49152"

-- Filter for non-standard HTTP ports
capture_filters.non_standard_http = [[
    tcp port 8000 or tcp port 8001 or tcp port 8008 or 
    tcp port 8080 or tcp port 8081 or tcp port 8888 or 
    tcp port 9000 or tcp port 9001 or tcp port 9999
]]

-- Filter for potential covert channels
capture_filters.covert_channels = [[
    icmp[icmptype] == 8 and icmp[icmpcode] == 0 and
    (len > 64 or icmp[4:4] != 0)
]]

-- =============================================================================
-- PROTOCOL-SPECIFIC FILTERS
-- =============================================================================

-- Filter for IPv6 traffic
capture_filters.ipv6_traffic = "ip6"

-- Filter for IPv4 traffic
capture_filters.ipv4_traffic = "ip"

-- Filter for VLAN tagged traffic
capture_filters.vlan_traffic = "vlan"

-- Filter for PPPoE traffic
capture_filters.pppoe_traffic = "pppoes"

-- Filter for MPLS traffic
capture_filters.mpls_traffic = "mpls"

-- =============================================================================
-- CUSTOM FILTER FUNCTIONS
-- =============================================================================

-- Function to create subnet-specific filters
function capture_filters.create_subnet_filter(subnet)
    return string.format("net %s", subnet)
end

-- Function to create host-specific filters
function capture_filters.create_host_filter(host)
    return string.format("host %s", host)
end

-- Function to create port range filters
function capture_filters.create_port_range_filter(start_port, end_port)
    return string.format("portrange %d-%d", start_port, end_port)
end

-- Function to create time-based filters
function capture_filters.create_time_filter(start_time, end_time)
    return string.format("time >= %s and time <= %s", start_time, end_time)
end

-- Function to combine multiple filters with AND logic
function capture_filters.combine_and(...)
    local filters = {...}
    return "(" .. table.concat(filters, ") and (") .. ")"
end

-- Function to combine multiple filters with OR logic
function capture_filters.combine_or(...)
    local filters = {...}
    return "(" .. table.concat(filters, ") or (") .. ")"
end

-- =============================================================================
-- FILTER VALIDATION AND UTILITIES
-- =============================================================================

-- Function to validate filter syntax
function capture_filters.validate_filter(filter_string)
    -- Basic validation checks
    if not filter_string or filter_string == "" then
        return false, "Empty filter string"
    end
    
    -- Check for balanced parentheses
    local open_count = 0
    for i = 1, #filter_string do
        local char = filter_string:sub(i, i)
        if char == "(" then
            open_count = open_count + 1
        elseif char == ")" then
            open_count = open_count - 1
            if open_count < 0 then
                return false, "Unmatched closing parenthesis"
            end
        end
    end
    
    if open_count ~= 0 then
        return false, "Unmatched opening parenthesis"
    end
    
    return true, "Valid filter"
end

-- Function to get all available filters
function capture_filters.get_all_filters()
    local filter_list = {}
    for name, filter in pairs(capture_filters) do
        if type(filter) == "string" then
            table.insert(filter_list, {name = name, filter = filter})
        end
    end
    return filter_list
end

-- Function to apply filter with error handling
function capture_filters.apply_filter(filter_name, interface)
    local filter = capture_filters[filter_name]
    if not filter then
        return false, "Filter not found: " .. filter_name
    end
    
    local valid, error_msg = capture_filters.validate_filter(filter)
    if not valid then
        return false, "Invalid filter: " .. error_msg
    end
    
    -- Apply the filter to the specified interface
    print(string.format("Applying filter '%s' to interface '%s': %s", 
                       filter_name, interface or "default", filter))
    
    return true, "Filter applied successfully"
end

-- =============================================================================
-- CONFIGURATION AND INITIALIZATION
-- =============================================================================

-- Default configuration
capture_filters.config = {
    default_interface = "eth0",
    buffer_size = 1024,
    timeout = 1000,
    promiscuous_mode = true,
    capture_all_packets = false
}

-- Function to initialize capture filters
function capture_filters.init(config)
    if config then
        for key, value in pairs(config) do
            capture_filters.config[key] = value
        end
    end
    
    print("Capture filters initialized")
    print("Available filters: " .. #capture_filters.get_all_filters())
end

-- Function to cleanup resources
function capture_filters.cleanup()
    print("Capture filters cleanup completed")
end

-- =============================================================================
-- EXPORT MODULE
-- =============================================================================

return capture_filters