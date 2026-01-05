-- Presonus Studio dissector for wireshark
-- (c) fenugrec 2025
-- GPLv3
--
-- place or symlink in $HOME/.local/lib/wireshark/plugins
-- to reload : Analyze->reload LUA plugins
-- 
-- tested on 1824c traffic


studiousb_protocol = Proto("studiousb", "Presonus StudioUSB protocol")

-- all fields must be 'registered' even if they may be missing e.g. payload
seq_id = ProtoField.uint32("studiousb.seq_id" , "seq_id" )
-- not sure how to combine this inline LUT with the later sel_table[]
sel = ProtoField.uint32("studiousb.sel" , "sel" , base.DEC, {
	[0] = "device",
	[0x64] = "mixer",
	[0x65] = "output",
})
u32 = ProtoField.uint32("studiousb.u32", "generic u32", base.HEX)
bflag = ProtoField.bool("studiousb.bflag", "bool")

studiousb_protocol.fields = { seq_id, sel, u32, bflag}

-- ******************* logging
-- sauce: https://wiki.wireshark.org/Lua/Examples/PostDissector
-- a debug logging function (adds into dissector proto tree)
local enable_logging = false   -- set this to true to enable it!!
enable_logging = true
local function initLog(tree, proto)
    if not enable_logging then
        -- if logging is disabled, we return a dummy function
        return function() return end
    end
    local log_tree = tree:add(proto, "Debug Log")
    log_tree:set_generated()
    -- return a function that when called will add a new child with the given text
    return function(str) log_tree:add(proto):set_text(str) end
end

-- ********************************
-- some defs, taken from kernel driver
sel_table = {
	[0] = {name="device"},
	[0x64] = {name="mixer"},
	[0x65] = {name="output"},
}

SC1810C_CMD_REQ = 160
SC1810C_CMD_F1 = 0x50617269
SC1810C_CMD_F2 = 0x14

SC1810C_SET_STATE_REQ = 161
SC1810C_SET_STATE_F1 = 0x64656D73
SC1810C_SET_STATE_F2 = 0xF4

SC1810C_GET_STATE_REQ = 162
SC1810C_GET_STATE_F1 = SC1810C_SET_STATE_F1
SC1810C_GET_STATE_F2 = SC1810C_SET_STATE_F2

-- these are indices inside the uint32[63] array composing the 'state' packet
statefield_table = {
	[58] = "48V SW",
	[59] = "Line SW",
	[60] = "Mute SW",
	[61] = "Mono SW",
	[62] = "A/B SW",
}

-- ****************************************
-- 'core' of the dissector
-- loosely based on "fpm.lua" example from wireshark wiki and netdaq dissector
-- ret 0 if error, (len) if succesfully parsed
--
-- CTL packets : sizeof=7*uint32 =28 B?
-- STATE packets : sizeof=63*uint32 = 252B
--
-- shit, this gets called with the Setup data as well when URB_CONTROL OUT.
-- Not sure how to get the first 7 bytes to be parsed by the basic USB decoder...
function studiousb_protocol.dissector(buf, pinfo, tree)
	length = buf:len()
	if length ~= 252 then return 0 end
	local log = initLog(tree,studiousb_protocol)
	log(string.format('len %u', length))

	pinfo.cols.protocol = studiousb_protocol.name
	local subtree = tree:add(studiousb_protocol, buf(), "StudioUSB Protocol Data")

	local selector = buf(0,4):le_uint() -- field 'a' in kernel code
	local field_b = buf(4,4):le_uint()
	local field_f1 = buf(8,4):le_uint()
	local field_f2 = buf(12,4):le_uint()

	subtree:add(sel, buf(0,4))
	selstring = sel_table[selector].name
	pinfo.cols.info:append(string.format(';sel %X(%s)', selector, selstring))
	subtree:add(u32, buf(4,4)):set_text(string.format('b field: %X', field_b))
	-- TODO : validate F1 or other
	subtree:add_le(u32, buf(8,4)):set_text(string.format('F1 marker: %X', field_f1))
	subtree:add_le(u32, buf(12,4)):set_text(string.format('F2 marker: %X', field_f2))

	-- other fields : label if known
	for field_idx = 4, 62 do
		field_text = statefield_table[field_idx]
		if not field_text then
			subtree:add_le(u32, buf(field_idx*4,4)):append_text(string.format(' (field #%u)', field_idx))
		else
			subtree:add(bflag, buf(field_idx*4,4)):append_text(string.format(' (%s)', field_text))
		end
	end
--	-- info colum : always start with seq number
--	pinfo.cols.info = string.format('seq=%u', seq_id_uint)
--	-- generic command header.
--	pinfo.cols.info:append(string.format(', CMD=0x%02X (%s)', cmd_id_uint, cmdstring))

--	subtree:add(cmd, buf(8,4)):append_text(string.format(' (%s)', cmdstring ))

	return length
end

set_plugin_info({
	version = "1.0",
	author = "fenugrec",
})
--- menu View->Internal->Dissector tab
--- also see epan/dissectors/packet-usb.c . Clear as mud
--- Also doesn't work well
DissectorTable.get("usb.control"):add(0xffff, studiousb_protocol)
--DissectorTable.get("usb.protocol"):add(0x80ef0201, studiousb_protocol)

