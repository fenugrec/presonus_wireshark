-- Presonus Studio dissector for wireshark
-- (c) fenugrec 2025
-- GPLv3
--
-- place or symlink in $HOME/.local/lib/wireshark/plugins
-- to reload : Analyze->reload LUA plugins
-- 
-- tested on 1824c traffic
--
-- sources:
-- https://github.com/royvegard/baton_studio/blob/main/src/lib.rs
-- https://git.kernel.org/pub/scm/linux/kernel/git/tiwai/sound.git/tree/sound/usb/mixer_s1810c.c


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

studiousb_protocol.fields = { seq_id, sel, u32}

-- not sure if this is a great idea ; add proper unique fields for everything.
-- One advantage is to allow plotting values in wireshark !
states_in={}
states_spdif={}
states_adat={}
states_daw={}
states_bus={}
for i = 1,2 do
	states_spdif[i] = ProtoField.uint32(string.format("studiousb.spdif%u",i), string.format("SPDIF %u", i), base.HEX)
	studiousb_protocol.fields[#studiousb_protocol.fields + 1] = states_spdif[i]
end
for i = 1,8 do
	states_in[i] = ProtoField.uint32(string.format("studiousb.in_%u",i), string.format("IN %u", i), base.HEX)
	states_adat[i] = ProtoField.uint32(string.format("studiousb.adat%u",i), string.format("ADAT %u", i), base.HEX)
	studiousb_protocol.fields[#studiousb_protocol.fields + 1] = states_in[i]
	studiousb_protocol.fields[#studiousb_protocol.fields + 1] = states_adat[i]
end
for i = 1,18 do
	states_daw[i] = ProtoField.uint32(string.format("studiousb.daw%u",i), string.format("DAW %u", i), base.HEX)
	states_bus[i] = ProtoField.uint32(string.format("studiousb.bus%u",i), string.format("BUS %u", i), base.HEX)
	studiousb_protocol.fields[#studiousb_protocol.fields + 1] = states_daw[i]
	studiousb_protocol.fields[#studiousb_protocol.fields + 1] = states_bus[i]
end

-- automate some of this. start_idx is 0-based, but pfield_table is 1-based to match human-readable channel numbers...
parse_fields = function (buf, subtree, pfield_table, start_idx, num_fields, name)
	temp_t = subtree:add(studiousb_protocol, buf(start_idx*4,num_fields*4), name)
	for i = 1, num_fields do
		temp_t:add_le(pfield_table[i], buf((start_idx + i - 1)*4, 4))
	end
	return temp_t
end

-- these are indices inside the uint32[63] array composing the 'state' packet
switch_table = {
	[58] = {name="48V SW", flagname="48v_sw", pf=nil},
	[59] = {name="Line SW", flagname="line_sw", pf=nil},
	[60] = {name="Mute SW", flagname="mute_sw", pf=nil},
	[61] = {name="Mono SW", flagname="mono_sw", pf=nil},
	[62] = {name="A/B SW", flagname="ab_sw", pf=nil},
}
for _,s in pairs(switch_table) do
	s.pf = ProtoField.bool(string.format('studiousb.%s', s.flagname), s.name)
	studiousb_protocol.fields[#studiousb_protocol.fields + 1] = s.pf
end

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

	-- make subtrees for groups of channel volumes
	in_t = parse_fields(buf, subtree, states_in, 4, 8, "IN")
	spdif_t = parse_fields(buf, subtree, states_spdif, 12, 2, "SPDIF")
	adat_t = parse_fields(buf, subtree, states_adat, 14, 8, "ADAT")
	daw_t = parse_fields(buf, subtree, states_daw, 22, 18, "DAW")
	bus_t = parse_fields(buf, subtree, states_bus, 40, 18, "BUS")

	for field_idx = 58, 62 do
		s = switch_table[field_idx]
		if not s then
			subtree:add_le(u32, buf(field_idx*4,4)):append_text(string.format(' (field #%u)', field_idx))
		else
			subtree:add(s.pf, buf(field_idx*4,4))
		end
	end

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

