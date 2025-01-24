function hasbit(x, p)
  return x % (p + p) >= p       
end

tsdebug_ll = Proto("tsdebug", "Tailscale debug")
PATH = ProtoField.string("tsdebug.PATH","PATH", base.ASCII)
SNAT_IP_4 = ProtoField.ipv4("tsdebug.SNAT_IP_4", "Pre-NAT Source IPv4 address")
SNAT_IP_6 = ProtoField.ipv6("tsdebug.SNAT_IP_6", "Pre-NAT Source IPv6 address")
DNAT_IP_4 = ProtoField.ipv4("tsdebug.DNAT_IP_4", "Pre-NAT Dest IPv4 address")
DNAT_IP_6 = ProtoField.ipv6("tsdebug.DNAT_IP_6", "Pre-NAT Dest IPv6 address")
tsdebug_ll.fields = {PATH, SNAT_IP_4, SNAT_IP_6, DNAT_IP_4, DNAT_IP_6}

function tsdebug_ll.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = tsdebug_ll.name
    packet_length = buffer:len()
    local offset = 0
    local subtree = tree:add(tsdebug_ll, buffer(), "Tailscale packet")

    -- -- Get path UINT16
    local path_id = buffer:range(offset, 2):le_uint()
    if     path_id == 0   then subtree:add(PATH, "FromLocal")
    elseif path_id == 1   then subtree:add(PATH, "FromPeer")
    elseif path_id == 2   then subtree:add(PATH, "Synthesized (Inbound / ToLocal)")
    elseif path_id == 3   then subtree:add(PATH, "Synthesized (Outbound / ToPeer)")
    elseif path_id == 254 then subtree:add(PATH, "Disco frame")
    end
    offset = offset + 2

    -- -- Get SNAT address
    local snat_addr_len = buffer:range(offset, 1):le_uint()
    if     snat_addr_len == 4 then subtree:add(SNAT_IP_4, buffer:range(offset + 1, snat_addr_len))
    elseif snat_addr_len > 0  then subtree:add(SNAT_IP_6, buffer:range(offset + 1, snat_addr_len))
    end
    offset = offset + 1 + snat_addr_len

    -- -- Get DNAT address
    local dnat_addr_len = buffer:range(offset, 1):le_uint()
    if     dnat_addr_len == 4 then subtree:add(DNAT_IP_4, buffer:range(offset + 1, dnat_addr_len))
    elseif dnat_addr_len > 0  then subtree:add(DNAT_IP_6, buffer:range(offset + 1, dnat_addr_len))
    end
    offset = offset + 1 + dnat_addr_len

    -- -- Handover rest of data to lower-level dissector
    local data_buffer = buffer:range(offset, packet_length-offset):tvb()
    if path_id == 254 then
        Dissector.get("tsdisco"):call(data_buffer, pinfo, tree)
    else
        Dissector.get("ip"):call(data_buffer, pinfo, tree)
    end
end

-- Install the dissector on link-layer ID 147 (User-defined protocol 0)
local eth_table = DissectorTable.get("wtap_encap")
eth_table:add(wtap.USER0, tsdebug_ll)


local ts_dissectors = DissectorTable.new("ts.proto", "Tailscale-specific dissectors", ftypes.STRING, base.NONE)


--
-- DISCO metadata dissector
--
tsdisco_meta = Proto("tsdisco", "Tailscale DISCO metadata")
DISCO_IS_DERP = ProtoField.bool("tsdisco.IS_DERP","From DERP")
DISCO_SRC_IP_4 = ProtoField.ipv4("tsdisco.SRC_IP_4", "Source IPv4 address")
DISCO_SRC_IP_6 = ProtoField.ipv6("tsdisco.SRC_IP_6", "Source IPv6 address")
DISCO_SRC_PORT = ProtoField.uint16("tsdisco.SRC_PORT","Source port", base.DEC)
DISCO_DERP_PUB = ProtoField.bytes("tsdisco.DERP_PUB", "DERP public key", base.SPACE)
tsdisco_meta.fields = {DISCO_IS_DERP, DISCO_SRC_PORT, DISCO_DERP_PUB, DISCO_SRC_IP_4, DISCO_SRC_IP_6}

function tsdisco_meta.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = tsdisco_meta.name
    packet_length = buffer:len()
    local offset = 0
    local subtree = tree:add(tsdisco_meta, buffer(), "DISCO metadata")

    -- Parse flags
    local from_derp = hasbit(buffer(offset, 1):le_uint(), 0)
    subtree:add(DISCO_IS_DERP, from_derp) -- Flag bit 0
    offset = offset + 1
    -- Parse DERP public key
    if from_derp then
        subtree:add(DISCO_DERP_PUB, buffer(offset, 32))
    end
    offset = offset + 32

    -- Parse source port
    subtree:add(DISCO_SRC_PORT, buffer:range(offset, 2):le_uint())
    offset = offset + 2

    -- Parse source address
    local addr_len = buffer:range(offset, 2):le_uint()
    offset = offset + 2
    if addr_len == 4 then subtree:add(DISCO_SRC_IP_4, buffer:range(offset, addr_len))
    else subtree:add(DISCO_SRC_IP_6, buffer:range(offset, addr_len))
    end
    offset = offset + addr_len

    -- Handover to the actual disco frame dissector
    offset = offset + 2 -- skip over payload len
    local data_buffer = buffer:range(offset, packet_length-offset):tvb()
    Dissector.get("disco"):call(data_buffer, pinfo, tree)
end

ts_dissectors:add(1, tsdisco_meta)

--
-- DISCO frame dissector
--
tsdisco_frame = Proto("disco", "Tailscale DISCO frame")
DISCO_TYPE = ProtoField.string("disco.TYPE", "Message type", base.ASCII)
DISCO_VERSION = ProtoField.uint8("disco.VERSION","Protocol version", base.DEC)
DISCO_TXID = ProtoField.bytes("disco.TXID", "Transaction ID", base.SPACE)
DISCO_NODEKEY = ProtoField.bytes("disco.NODE_KEY", "Node key", base.SPACE)
DISCO_PONG_SRC = ProtoField.ipv6("disco.PONG_SRC", "Pong source")
DISCO_PONG_SRC_PORT = ProtoField.uint16("disco.PONG_SRC_PORT","Source port", base.DEC)
DISCO_UNKNOWN = ProtoField.bytes("disco.UNKNOWN_DATA", "Trailing data", base.SPACE)
tsdisco_frame.fields = {DISCO_TYPE, DISCO_VERSION, DISCO_TXID, DISCO_NODEKEY, DISCO_PONG_SRC, DISCO_PONG_SRC_PORT, DISCO_UNKNOWN}

function tsdisco_frame.dissector(buffer, pinfo, tree)
    packet_length = buffer:len()
    local offset = 0
    local subtree = tree:add(tsdisco_frame, buffer(), "DISCO frame")

    -- Message type
    local message_type = buffer(offset, 1):le_uint()
    offset = offset + 1
    if     message_type == 1 then subtree:add(DISCO_TYPE, "Ping")
    elseif message_type == 2 then subtree:add(DISCO_TYPE, "Pong")
    elseif message_type == 3 then subtree:add(DISCO_TYPE, "Call me maybe")
    end

    -- Message version
    local message_version = buffer(offset, 1):le_uint()
    offset = offset + 1
    subtree:add(DISCO_VERSION, message_version)

    -- TXID (Ping / Pong)
    if message_type == 1 or message_type == 2 then
        subtree:add(DISCO_TXID, buffer(offset, 12))
        offset = offset + 12
    end

    -- NodeKey (Ping)
    if message_type == 1 then
        subtree:add(DISCO_NODEKEY, buffer(offset, 32))
        offset = offset + 32
    end

    -- Src (Pong)
    if message_type == 2 then
        subtree:add(DISCO_PONG_SRC, buffer:range(offset, 16))
        offset = offset + 16
    end
    -- Src port (Pong)
    if message_type == 2 then
        subtree:add(DISCO_PONG_SRC_PORT, buffer(offset, 2):le_uint())
        offset = offset + 2
    end

    -- TODO(tom): Parse CallMeMaybe.MyNumber

    local trailing = buffer:range(offset, packet_length-offset)
    if trailing:len() > 0 then
        subtree:add(DISCO_UNKNOWN, trailing)
    end
end

ts_dissectors:add(2, tsdisco_frame)