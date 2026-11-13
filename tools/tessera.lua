-- tessera.lua : TESSERA stego transport v2 dissector
local p = Proto("tessera", "TESSERA Stego Transport")

local types = {
    [1] = "SYN",
    [2] = "DATA",
    [3] = "ACK",
    [4] = "NACK",
    [5] = "FIN",
    [6] = "SYN-ACK",
    [7] = "DONE"
}

local f = p.fields
f.magic   = ProtoField.uint16("tessera.magic",   "Magic",          base.HEX)
f.version = ProtoField.uint8 ("tessera.version", "Version",        base.DEC, nil, 0xF0)
f.flags   = ProtoField.uint8 ("tessera.flags",   "Flags",          base.HEX, nil, 0x0F)
f.ptype   = ProtoField.uint8 ("tessera.type",    "Type",           base.DEC, types)
f.session = ProtoField.uint32("tessera.session", "Session ID",     base.HEX)
f.seq     = ProtoField.uint32("tessera.seq",     "Sequence",       base.DEC)
f.tile    = ProtoField.uint16("tessera.tile",    "Tile index",     base.DEC)
f.frag    = ProtoField.uint16("tessera.frag",    "Fragment index", base.DEC)
f.tag     = ProtoField.uint32("tessera.tag",     "Tag (CRC32/Keyed)", base.HEX)
f.payload = ProtoField.bytes ("tessera.payload", "Payload")

function p.dissector(buf, pinfo, tree)
    if buf:len() < 20 then return 0 end
    if buf(0, 2):uint() ~= 0x5354 then return 0 end -- Magic "ST" check

    pinfo.cols.protocol = "TESSERA"

    local t = tree:add(p, buf(), "TESSERA Stego Transport")
    t:add(f.magic,   buf(0, 2))
    t:add(f.version, buf(2, 1))
    t:add(f.flags,   buf(2, 1))
    t:add(f.ptype,   buf(3, 1))
    t:add(f.session, buf(4, 4))
    t:add(f.seq,     buf(8, 4))
    t:add(f.tile,    buf(12, 2))
    t:add(f.frag,    buf(14, 2))
    t:add(f.tag,     buf(16, 4))
    if buf:len() > 20 then
        t:add(f.payload, buf(20, buf:len() - 20))
    end

    local ty = types[buf(3, 1):uint()] or "?"
    pinfo.cols.info = string.format("%s tile=%d seq=%d len=%d",
                                    ty, buf(12, 2):uint(), buf(8, 4):uint(), buf:len())
    return buf:len()
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(9998, p)
udp_table:add(9999, p)
