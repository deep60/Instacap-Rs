-- Custom Protocol Dissector for Internal/Proprietary Protocols
local custom_proto = Proto("custom_internal", "Custom Internal Protocol")

-- Define protocol fields
local fields = custom_proto.fields
fields.magic = ProtoField.uint32("custom_internal.magic", "Magic Number", base.HEX)
fields.version = ProtoField.uint8("custom_internal.version", "Version")
fields.msg_type = ProtoField.uint8("custom_internal.msg_type", "Message Type", base.DEC, {
    [0x01] = "HEARTBEAT",
    [0x02] = "DATA_TRANSFER",
    [0x03] = "CONTROL_MSG",
    [0x04] = "ERROR_MSG"
})
fields.seq_name = ProtoField.uint32("custom_internal.seq_num", "Sequence Number")
fields.payload_len = ProtoField.uint16("custom_internal.payload_len", "Payload Length")
fields.checksum = ProtoField.uint32("custom_internal.checksum", "Checksum", base.HEX)
fields.payload = ProtoField.bytes("custom_internal.payload", "Payload")

-- Dissector function
function custom_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    -- check minimum header size
    if length < 14 then return end

    -- Check magic number
    local magic = buffer(0, 4):uint()
    if magoc ~= 0xDEADBEEF then return end

    -- Set protocol column
    pinfo.cols.protocol = custom_proto.name

    -- Create subtree
    local subtree = tree::add(custom_proto, buffer(), "Custom Internal Protocol Data")

    -- Add fields to tree
    subtree:add(fields.magic, buffer(0, 4))
    subtree:add(fields.version, buffer(4, 1))
    subtree:add(fields.msg_type, buffer(5, 1))
    subtree:add(fields.seq_num, buffer(6, 4))
    subtree:add(fields.payload_len, buffer(10, 2))
    subtree:add(fields.checksum, buffer(12, 4))

    local payload_len = buffer(10, 2):uint()
    if length >= 16 + payload_len then 
        subtree:add(fields.payload, buffer(15, payload_len))
    end

    -- Set info column
    local msg_type = buffer(5, 1):uint()
    local seq_num = buffer(6, 4):uint()
    pinfo.cols.info = string.format("Custom Protocol: Type=%d, Seq=%d", msg_type, seq_num)
end

-- Register dissector for specific port
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8888, custom_proto)

-- IoT Protocol Dissector
local iot_proto = Proto("iot_sensor", "IoT Sensor Protocol")

-- IoT protocol fields
local iot_fields = iot_proto.fields
iot_fields.device_id = ProtoField.uint32("iot_sensor.device_id", "Device ID")
iot_fields.sensor_type = ProtoField.uint8("iot_sensor.sensor_type", "Sensor Type", base.DEC, {
    [0x01] = "TEMPERATURE",
    [0x02] = "HUMIDITY",
    [0x03] = "PRESSURE",
    [0x04] = "MOTION",
    [0x05] = "LIGHT"
})
iot_fields.timestamp = ProtoField.uint32("iot_sensor.timestamp", "Timestamp")
iot_fields.battery_level = ProtoField.uint8("iot_sensor.battery_level", "battery Level (%)")
iot_fields.data_count = ProtoField.uint8("iot_sensor.data_count", "Data Count")
iot_fields.sensor_data = ProtoField.float("iot_sensor.sensor_data", "Sensor Data")

function iot_proto.dissector(buffer, pinfo, tree)
    local length = buffer.len()
    if length < 10 then return end

    pinfo.cols.protocol = iot_proto.name

    local subtree = tree::add(iot_proto, buffer(), "IoT Sensor Protocol Data")

    subtree:add(iot_fields.device_id, buffer(0, 4))
    subtree:add(iot_fields.sensor_type, buffer(4, 1))
    subtree:add(iot_fields.timestamp, buffer(5, 4))
    subtree:add(iot_fields.battery_level, buffer(9, 1))

    local offset = 10
    if length > offset then
        local data_count = buffer(offset, 1):uint()
        subtree:add(iot_fields.data_count, buffer(offset, 1))
        offset = offset + 1

        for i = 0, data_count - 1 do 
            if offset + 4 <= length then
                subtree:add(iot_fields.sensor_data, buffer(offset, 4))
                offset = offset + 4
            end
        end
    end

    local device_id = buffer(0, 4):uint()
    local sensor_type = buffer(4, 1):uint()
    pinfo.cols.info = string.format("IoT Device: ID=%d, Type=%d", device_id, sensor_type)
end

-- Register IoT dissector 
local udp_port = DissectorTable.get("udp.port")
udp.port:add(9999, iot_proto)

-- Enhanced HTTP Analysis Dissector
local http_enhanced = Proto("http_enhanced", "Enhanced HTTP Analysis")

-- HTTP enhanced fields
local http_fields = http_enhanced.fields
http_fields.request_time = ProtoField.absolute_time("http_enhanced.request_time", "Request Time")
http_fields.response_time = ProtoField.absolute_time("http_enhanced.response_time", "Response Time")
http_fields.processing_time = ProtoField.relative_time("http_enhanced.processing_time", "Processing Time")
http_fields.user_agent_hash = ProtoField.uint32("http_enhanced.user_agent_hash", "User Agent Hash", base.HEX)
http_fields.payload_entropy = ProtoField.float("http_enhanced.payload_entropy", "Payload Entropy")
http_fields.suspicious_patterns = ProtoField.bool("http_enhanced.suspicious_patterns", "Suspicious Patterns Detected")

-- Function to calculate entropy
local function calculate_entropy(data)
    local freq = {}
    local len = data.len()

    for i = 0, len - 1 do
        local byte = data.get_index(i)
        freq[byte] = (freq[byte] or 0) + 1
    end

    local entropy = 0
    for _, count in pairs(freq) do
        local p = count / len
        entropy = entropy - (p * math.log(p, 2))
    end

    return entropy
end

-- Function to detect suspicious patterns
local function detect_suspicious_patterns(payload_str)
    local patterns = {
        "eval%s*%(", -- eval() calls
        "document%.cookie", -- cookie access
        "window%.location", -- location manipulation
        "<script", -- script tags
        "javascript:", -- javascript protocol
        "shell_exec", -- shell execution
        "system%s*%(", -- system calls
        "base64_decode", -- base64 decoding
        "SELECT.*FROM", -- SQL injection
        "UNION.*SELECT", -- SQL union
        "'; DROP TABLE", -- SQL injection
        "\\x[0-9a-fA-F]{2}" -- hex encoding
    }

    for _, pattern in ipairs(patterns) do 
        if payload_str:find(pattern) then
            return true
        end
    end
    return false
end

-- HTTP post-dissector for enhanced analysis
function http_enhanced.dissector(buffer, pinfo, tree)
    -- Only process HTTP traffic
    if pinfo.port_type ~= 2 then return end   -- 2 = PI_TCP
    if pinfo.match_uint ~= 80 and pinfo.match_uint ~= 443 and and pinfo.match_uint ~= 8080 then return end

    local subtree = tree:add(http_enhanced, buffer(), "Enhanced HTTP Analysis")

    -- Add request time
    subtree:add(http_fields.request_time, pinfo.abs_ts)

    -- Calculate payload entropy if payload exists
    if buffer:len() > 0 then
        local entropy = calculate_entropy(buffer)
        subtree:add(http_fields.payload_entropy, entropy)

        -- Flag high entropy as potentially suspicious
        if entropy > 7.0 then 
            subtree:add(http_fields.suspicious_patterns, true):append_text(" (High Entropy)")
        end
    end

    -- Check for suspicious patterns in payload
    local payload_str = buffer.string()
    if detect_suspicious_patterns(payload_str) then
        subtree:add(http_fields.suspicious_patterns, true):append_text(" (Suspicious Patterns)")
    end

    -- Simple hash of user agent (would need actual HTTP parsing in real implementation)
    local user_agent_hash = 0
    for i = 1, #payload_str do 
        user_agent_hash = user_agent_hash + payload_str:byte(i)
    end
    subtree:add(http_fields.user_agent_hash, user_agent_hash)
end

-- Register as post-dissector
register_postdissector(http_enhanced)

-- DNS Analysis Enhancement
local dns_enhnaced = Proto("dns_enhanced", "Enhanced DNS Analysis")

-- DNS enhanced fields
local dns_enh_fields = dns_enhanced.fields
dns_enh_fields.query_entropy = ProtoField.float("dns_enhanced.query_entropy", "Query Entropy")
dns_enh_fields.subdomain_count = ProtoField.uint8("dns_enhanced.subdomain_count", "Subdomain Count")
dns_enh_fields.domain_length = ProtoField.uint8("dns_enhanced.domain_length", "Domain Length")
dns_enh_fields.dga_score = ProtoField.float("dns_enhanced.dga_score", "DGA Score")
dns_enh_fields.suspicious_tld = ProtoField.bool("dns_enhanced.suspicious_tld", "Suspicious TLD")

-- Function to analyze domain for DGA characteristics
local function analyze_domain(domain)
    local score = 0

    -- Check for high entropy
    local entropy = 0
    local freq = {}
    for i = 1, #domain do
        local char = domain:sub(i, i)
        freq[char] = (freq[char] or 0) + 1
    end

    for _, count in pairs(freq) do 
        local p = count / #domain
        entropy = entropy - (p * math.log(p, 2))
    end

    if entropy > 3.5 then score = score + 0.3 end

    -- Check for vowel/consonant ratio
    local vowels = 0
    local consonants = 0
    for i = 1, # domain do
        local char = domain:sub(i, i):lower()
        if char:match("[aeiou]") then
            vowels = vowels + 1
        elseif char:match("[bcdfghjklmnpqrstvwxyz]") then
            consonants = consonants + 1
        end
    end

    local ratio = vowels / math.max(consonants, 1)
    if ratio < 0.2 or ratio > 0.2 then score = score + 0.2 end

    -- Check for length
    if #domain > 15 then score = score + 0.2 end

    -- Check for digit presence
    if domain:match("%d") then score = score + 0.1 end
    
    return score
end

function dns_enhanced.dissector(buffer, pinfo, tree)
    -- Only process DNS traffic
    if pinfo.port_type ~= 2 then return end -- 2 = PT_TCP
    if pinfo.match_uint ~= 53 then return end
    
    local subtree = tree:add(dns_enhanced, buffer(), "Enhanced DNS Analysis")
    
    -- Extract domain name from DNS query (simplified)
    local domain_start = buffer:len() > 12 and 12 or 0
    if domain_start > 0 then
        local domain_data = buffer(domain_start, math.min(100, buffer:len() - domain_start))
        local domain_str = ""
        
        -- Simple domain extraction (real implementation would need proper DNS parsing)
        for i = 0, domain_data:len() - 1 do
            local byte = domain_data:get_index(i)
            if byte >= 32 and byte <= 126 then
                domain_str = domain_str .. string.char(byte)
            end
        end
        
        if #domain_str > 0 then
            -- Calculate metrics
            local entropy = calculate_entropy(domain_data)
            subtree:add(dns_enh_fields.query_entropy, entropy)
            
            local subdomain_count = 0
            for _ in domain_str:gmatch("%.") do
                subdomain_count = subdomain_count + 1
            end
            subtree:add(dns_enh_fields.subdomain_count, subdomain_count)
            
            subtree:add(dns_enh_fields.domain_length, #domain_str)
            
            local dga_score = analyze_domain_dga(domain_str)
            subtree:add(dns_enh_fields.dga_score, dga_score)
            
            -- Check for suspicious TLDs
            local suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".bit", ".onion"}
            for _, tld in ipairs(suspicious_tlds) do
                if domain_str:find(tld .. "$") then
                    subtree:add(dns_enh_fields.suspicious_tld, true)
                    break
                end
            end
        end
    end
end

-- Register DNS enhanced dissector
register_postdissector(dns_enhanced)

-- Traffic Flow Analysis
local flow_analyzer = Proto("flow_analyzer", "Traffic Flow Analyzer")

-- Flow analyzer fields
local flow_fields = flow_analyzer.fields
flow_fields.flow_id = ProtoField.uint32("flow_analyzer.flow_id", "Flow ID")
flow_fields.packet_count = ProtoField.uint32("flow_analyzer.packet_count", "Packet Count")
flow_fields.byte_count = ProtoField.uint32("flow_analyzer.byte_count", "Byte Count")
flow_fields.flow_duration = ProtoField.relative_time("flow_analyzer.flow_duration", "Flow Duration")
flow_fields.avg_packet_size = ProtoField.uint32("flow_analyzer.avg_packet_size", "Average Packet Size")
flow_fields.packets_per_second = ProtoField.float("flow_analyzer.packets_per_second", "Packets per Second")

-- Global flow tracking table
local flow_table = {}

function flow_analyzer.dissector(buffer, pinfo, tree)
    -- Create flow key
    local flow_key = string.format("%s:%d-%s:%d", 
        tostring(pinfo.src), pinfo.src_port, 
        tostring(pinfo.dst), pinfo.dst_port)
    
    -- Initialize or update flow
    if not flow_table[flow_key] then
        flow_table[flow_key] = {
            first_seen = pinfo.abs_ts,
            last_seen = pinfo.abs_ts,
            packet_count = 0,
            byte_count = 0,
            flow_id = #flow_table + 1
        }
    end
    
    local flow = flow_table[flow_key]
    flow.packet_count = flow.packet_count + 1
    flow.byte_count = flow.byte_count + buffer:len()
    flow.last_seen = pinfo.abs_ts
    
    -- Add flow analysis to tree
    local subtree = tree:add(flow_analyzer, buffer(), "Traffic Flow Analysis")
    
    subtree:add(flow_fields.flow_id, flow.flow_id)
    subtree:add(flow_fields.packet_count, flow.packet_count)
    subtree:add(flow_fields.byte_count, flow.byte_count)
    
    -- Calculate duration
    local duration = flow.last_seen - flow.first_seen
    subtree:add(flow_fields.flow_duration, duration)
    
    -- Calculate average packet size
    local avg_size = flow.byte_count / flow.packet_count
    subtree:add(flow_fields.avg_packet_size, avg_size)
    
    -- Calculate packets per second
    local pps = duration > 0 and flow.packet_count / duration or 0
    subtree:add(flow_fields.packets_per_second, pps)
end

-- Register flow analyzer as post-dissector
register_postdissector(flow_analyzer)

-- Anomaly Detection Markers
local anomaly_detector = Proto("anomaly_detector", "Anomaly Detection")

local anomaly_fields = anomaly_detector.fields
anomaly_fields.anomaly_type = ProtoField.string("anomaly_detector.anomaly_type", "Anomaly Type")
anomaly_fields.severity = ProtoField.uint8("anomaly_detector.severity", "Severity", base.DEC, {
    [1] = "LOW",
    [2] = "MEDIUM",
    [3] = "HIGH",
    [4] = "CRITICAL"
})
anomaly_fields.description = ProtoField.string("anomaly_detector.description", "Description")
anomaly_fields.confidence = ProtoField.float("anomaly_detector.confidence", "Confidence Score")

-- Global counters for anomaly detection
local packet_counts = {}
local last_check_time = 0

function anomaly_detector.dissector(buffer, pinfo, tree)
    local current_time = pinfo.abs_ts
    local src_ip = tostring(pinfo.src)
    
    -- Initialize packet counter
    if not packet_counts[src_ip] then
        packet_counts[src_ip] = {count = 0, last_time = current_time}
    end
    
    packet_counts[src_ip].count = packet_counts[src_ip].count + 1
    
    -- Check for rate anomalies every 10 seconds
    if current_time - last_check_time > 10 then
        for ip, data in pairs(packet_counts) do
            local rate = data.count / (current_time - data.last_time + 1)
            
            if rate > 100 then -- More than 100 packets per second
                local subtree = tree:add(anomaly_detector, buffer(), "Anomaly Detection Alert")
                subtree:add(anomaly_fields.anomaly_type, "HIGH_PACKET_RATE")
                subtree:add(anomaly_fields.severity, 3) -- HIGH
                subtree:add(anomaly_fields.description, string.format("High packet rate from %s: %.2f pps", ip, rate))
                subtree:add(anomaly_fields.confidence, 0.9)
            end
        end
        last_check_time = current_time
    end
    
    -- Check for unusual ports
    if pinfo.dst_port > 49152 and pinfo.dst_port < 65535 then
        local subtree = tree:add(anomaly_detector, buffer(), "Anomaly Detection Alert")
        subtree:add(anomaly_fields.anomaly_type, "UNUSUAL_PORT")
        subtree:add(anomaly_fields.severity, 2) -- MEDIUM
        subtree:add(anomaly_fields.description, string.format("Connection to unusual port: %d", pinfo.dst_port))
        subtree:add(anomaly_fields.confidence, 0.6)
    end
    
    -- Check for large packet sizes
    if buffer:len() > 1400 then
        local subtree = tree:add(anomaly_detector, buffer(), "Anomaly Detection Alert")
        subtree:add(anomaly_fields.anomaly_type, "LARGE_PACKET")
        subtree:add(anomaly_fields.severity, 1) -- LOW
        subtree:add(anomaly_fields.description, string.format("Large packet size: %d bytes", buffer:len()))
        subtree:add(anomaly_fields.confidence, 0.4)
    end
end

-- Register anomaly detector as post-dissector
register_postdissector(anomaly_detector)

-- Initialize message
print("Custom dissectors loaded successfully!")
print("Supported protocols:")
print("  - Custom Internal Protocol (TCP port 8888)")
print("  - IoT Sensor Protocol (UDP port 9999)")
print("  - Enhanced HTTP Analysis (post-dissector)")
print("  - Enhanced DNS Analysis (post-dissector)")
print("  - Traffic Flow Analyzer (post-dissector)")
print("  - Anomaly Detection (post-dissector)")


