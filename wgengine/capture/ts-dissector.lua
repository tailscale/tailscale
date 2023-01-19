tsdebug_ll = Proto("tsdebug", "Tailscale debug")
PATH = ProtoField.string("tsdebug.PATH","PATH", base.ASCII)
tsdebug_ll.fields = {PATH}

function tsdebug_ll.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = tsdebug_ll.name
    packet_length = buffer:len()
    local offset = 0
    local subtree = tree:add(tsdebug_ll, buffer(), "Tailscale packet")

    -- -- Get path UINT16
    local path_id = buffer:range(offset, 2):le_uint()
    if     path_id == 0 then subtree:add(PATH, "FromLocal")
    elseif path_id == 1 then subtree:add(PATH, "FromPeer")
    elseif path_id == 2 then subtree:add(PATH, "Synthesized (Inbound / ToLocal)")
    elseif path_id == 3 then subtree:add(PATH, "Synthesized (Outbound / ToPeer)")
    end
    offset = offset + 2

    -- -- Handover rest of data to ip dissector
    local data_buffer = buffer:range(offset, packet_length-offset):tvb()
    Dissector.get("ip"):call(data_buffer, pinfo, tree)
end

-- Install the dissector on link-layer ID 147 (User-defined protocol 0)
local eth_table = DissectorTable.get("wtap_encap")
eth_table:add(wtap.USER0, tsdebug_ll)