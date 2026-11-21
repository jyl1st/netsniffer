-- NetSniffer 应用识别。与 sniffer/dissect/app_detect.py 的对应关系：
-- Python 判据                        Lua 判据                         字段中的依据
-- http_info / tls_record_header      HTTP 首行 / TLS 记录头            内容特征
-- _ssh_banner                        SSH 版本横幅                     内容特征
-- TCP_PORTS / UDP_PORTS              同一端口表，目的端口优先         port_guess
-- _validated_summary                 DNS、DHCP、NTP、SSDP 最小结构     端口（内容已校验）
-- quic_long_header                   QUIC 连接 ID、版本和长度边界       弱特征
-- _rejected / 强特征与候选不符        有负载时标记 mismatch
-- 只读当前帧的传输层字节，保持 TCP 重组和应用详情解析独立于本插件。

-- 同时从个人插件目录和 -X lua_script 加载时复用同一次注册。
if package.loaded.netsniffer_appid then return end

local protocol = Proto("netsniffer", "NetSniffer 应用识别")
local app = ProtoField.string("netsniffer.app", "应用识别")
local basis = ProtoField.string("netsniffer.basis", "识别依据")
local port_guess = ProtoField.string("netsniffer.port_guess", "端口猜测")
local mismatch = ProtoField.bool("netsniffer.mismatch", "内容和端口不符")
protocol.fields = {app, basis, port_guess, mismatch}

local tcp_source = Field.new("tcp.srcport")
local tcp_target = Field.new("tcp.dstport")
local tcp_header = Field.new("tcp.hdr_len")
local tcp_length = Field.new("tcp.len")
local udp_source = Field.new("udp.srcport")
local udp_target = Field.new("udp.dstport")
local udp_length = Field.new("udp.length")

local tcp_ports = {[22] = "SSH", [53] = "DNS", [80] = "HTTP", [443] = "TLS",
                   [8000] = "HTTP", [8080] = "HTTP", [8443] = "TLS"}
local udp_ports = {[53] = "DNS", [67] = "DHCP", [68] = "DHCP", [123] = "NTP",
                   [1900] = "SSDP", [5353] = "mDNS"}
local dns_opcodes = {[0] = true, [1] = true, [2] = true, [4] = true, [5] = true, [6] = true}

local function u16(data, at)
    return data:byte(at) * 256 + data:byte(at + 1)
end

local function http_line(data, ssdp)
    local prefix = data:sub(1, 2048)
    local stop = prefix:find("\r\n", 1, true)
    if not stop and #prefix < #data then return false end
    local line = stop and prefix:sub(1, stop - 1) or prefix:gsub("\r$", "")
    local reason = line:match("^HTTP/1%.[01] [1-5][0-9][0-9](.*)$")
    if reason then return reason == "" or reason:match("^ [\t -~\128-\255]*$") ~= nil end
    local method = line:match("^([A-Z][A-Z0-9_%-]*) [!-~]+ HTTP/1%.[01]$")
    return method ~= nil and (not ssdp or method == "M-SEARCH" or method == "NOTIFY")
end

local function strong_tcp(data)
    local first = data:byte(1)
    if first >= 65 and first <= 90 and http_line(data, false) then return "HTTP" end
    if #data >= 5 and first >= 20 and first <= 24 then
        local version, length = u16(data, 2), u16(data, 4)
        if version >= 0x0300 and version <= 0x0303 and length <= 18432 and (length > 0 or first == 23) then
            return "TLS"
        end
    end
    if data:sub(1, 4) == "SSH-" then
        local line = data:sub(1, 255):match("^([^\n]+)\n")
        local version, tail
        if line then version, tail = line:gsub("\r$", ""):match("^SSH%-([0-9.]+)%-[!-~]+(.*)$") end
        if (version == "2.0" or version == "1.99" or version == "1.5")
                and (tail == "" or tail:match("^ [ -~]*$")) then return "SSH" end
    end
end

local function skip_dns_name(data, at)
    local first = at
    while at <= #data and at - first < 255 do
        local label = data:byte(at)
        if label == 0 then return at + 1 end
        if label >= 192 then
            if at + 1 <= #data and (u16(data, at) & 0x3fff) + 1 < at then return at + 2 end
            return nil
        end
        if label > 63 or at + label > #data then return nil end
        at = at + label + 1
    end
end

local function dns_header(data, is_tcp)
    if is_tcp then
        if #data < 2 then return false end
        local length = u16(data, 1)
        if length < 12 or length > #data - 2 then return false end
        data = data:sub(3, length + 2)
    end
    if #data < 12 then return false end
    local flags = u16(data, 3)
    if not dns_opcodes[(flags >> 11) & 15] or (flags & 0x40) ~= 0 then return false end
    local questions = u16(data, 5)
    local records = u16(data, 7) + u16(data, 9) + u16(data, 11)
    if questions + records > 256 then return false end
    local at = 13
    for index = 1, questions + records do
        at = skip_dns_name(data, at)
        if not at then return false end
        if index <= questions then
            at = at + 4
        else
            if at + 9 > #data then return false end
            at = at + 10 + u16(data, at + 8)
        end
        if at > #data + 1 then return false end
    end
    return data:sub(at):match("^%z*$") ~= nil
end

local function dhcp_options(data)
    if #data < 240 or data:sub(237, 240) ~= "\x63\x82\x53\x63" then return false end
    local op, hardware_length = data:byte(1), data:byte(3)
    if (op ~= 1 and op ~= 2) or hardware_length < 1 or hardware_length > 16 then return false end
    local at, count, message = 241, 0, nil
    while at <= #data and at < 4337 and count < 256 do
        local code, length = data:byte(at, at + 1)
        if code == 255 then return message ~= nil end
        if code == 0 then
            at = at + 1
        else
            if not length or at + 1 + length > #data then return false end
            if code == 53 then
                if length ~= 1 or message then return false end
                message = data:byte(at + 2)
                if message < 1 or message > 8 then return false end
            end
            at, count = at + 2 + length, count + 1
        end
    end
    return false
end

local function ntp_header(data)
    if #data < 48 or #data % 4 ~= 0 then return false end
    local flags, stratum = data:byte(1, 2)
    local version, mode = (flags >> 3) & 7, flags & 7
    local poll, precision = string.unpack("bb", data, 3)
    return version >= 1 and version <= 4 and mode >= 1 and mode <= 5 and stratum <= 16
        and poll >= -6 and poll <= 17 and precision >= -40 and precision <= 5
        and data:sub(41, 48):match("[^%z]") ~= nil
end

local function validates(hint, data, is_tcp)
    if hint == "DNS" or hint == "mDNS" then return dns_header(data, is_tcp) end
    if hint == "DHCP" then return dhcp_options(data) end
    if hint == "NTP" then return ntp_header(data) end
    if hint == "SSDP" then return http_line(data, true) end
    return false
end

local function quic_varint(data, at)
    local first = data:byte(at)
    if not first then return nil end
    local size = 1 << (first >> 6)
    if at + size - 1 > #data then return nil end
    local value = first & 63
    for index = at + 1, at + size - 1 do value = (value << 8) | data:byte(index) end
    return value, at + size
end

local function quic_long_header(data, on_443)
    local flags = data:byte(1)
    if #data < 7 or (flags & 0x80) == 0 then return false end
    local version = string.unpack(">I4", data, 2)
    local known = version == 1 or version == 0x6b3343cf or (version & 0xffffff00) == 0xff000000
    if not (known or on_443) or (version ~= 0 and (flags & 0x40) == 0) then return false end
    local dcid = data:byte(6)
    local at = 7 + dcid
    if dcid > 20 or at > #data then return false end
    local scid = data:byte(at)
    at = at + 1 + scid
    if scid > 20 or at > #data then return false end
    if version == 0 then return (#data - at + 1) % 4 == 0 end
    local kind = (flags >> 4) & 3
    local v2 = version == 0x6b3343cf
    if kind == (v2 and 0 or 3) then return known and #data - at + 1 >= 17 end
    if kind == (v2 and 1 or 0) then
        if #data < 1200 then return false end
        local token, next_at = quic_varint(data, at)
        if not token then return false end
        at = next_at + token
    end
    local size, next_at = quic_varint(data, at)
    return size ~= nil and size >= 17 and size <= #data - next_at + 1
        and (known or size == #data - next_at + 1)
end

local function identify(data, is_tcp, source, target)
    local ports = is_tcp and tcp_ports or udp_ports
    local dst_guess, src_guess = ports[target], ports[source]
    local table_guess = dst_guess or src_guess
    local on_quic_port = not is_tcp and (source == 443 or target == 443)
    local guess = table_guess or (on_quic_port and "QUIC" or nil)
    if #data == 0 then return nil, nil, guess end
    if is_tcp then
        local strong = strong_tcp(data)
        if strong then return strong, "内容特征", guess end
    end
    if table_guess then
        -- 两端都命中时先校验目的端，失败后再校验不同的源端候选。
        if dst_guess and validates(dst_guess, data, is_tcp) then return dst_guess, "端口（内容已校验）", guess end
        if src_guess and src_guess ~= dst_guess and validates(src_guess, data, is_tcp) then
            return src_guess, "端口（内容已校验）", guess
        end
    elseif not is_tcp and quic_long_header(data, on_quic_port) then
        return "QUIC", "弱特征", guess
    end
    return nil, nil, guess
end

function protocol.dissector(tvb, pinfo, tree)
    local tcp, udp = tcp_source(), udp_source()
    local is_tcp = tcp ~= nil and (udp == nil or tcp.offset < udp.offset)
    local source, target, header, size
    if is_tcp then
        local header_field, length_field = tcp_header(), tcp_length()
        if not header_field or not length_field then return end
        source, target, header, size = tcp, tcp_target(), header_field.value, length_field.value
    elseif udp then
        local length_field = udp_length()
        if not length_field then return end
        source, target, header, size = udp, udp_target(), 8, length_field.value - 8
    end
    if not target or not source or header < (is_tcp and 20 or 8) or size < 0 then return end
    -- 从本帧 TVB 读取，避免误用原生解析器的已重组应用数据。
    local at = source.offset
    if at + header > tvb:len() or tvb(at, 2):uint() ~= source.value or tvb(at + 2, 2):uint() ~= target.value then
        return
    end
    local length = math.min(size, tvb:len() - at - header)
    local data = length > 0 and tvb(at + header, length):raw() or ""
    local identified, reason, guess = identify(data, is_tcp, source.value, target.value)
    if not identified and not guess then return end
    local node = tree:add(protocol, tvb(at, header + length))
    if identified then
        node:add(app, identified):set_generated()
        node:add(basis, reason):set_generated()
    end
    if guess then node:add(port_guess, guess):set_generated() end
    node:add(mismatch, length > 0 and guess ~= nil and guess ~= identified):set_generated()
end

register_postdissector(protocol)
package.loaded.netsniffer_appid = true
