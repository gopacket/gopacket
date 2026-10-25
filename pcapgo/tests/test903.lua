-- prevent wireshark loading this file as a plugin
if not _G['pcapng_test_gen'] then return end


local block = require "blocks"
local input = require "input"


local test = {
    category    = 'difficult',
    description = "idb with binary resolution finer than a nanosecond",
}


local timestamp = UInt64(0x30000000, 0x16a30370)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 0, "eth0")
                    :addOption( block.OptionFormat ('if_tsresol', "B", 0x9e) )

    self.blocks = {
        block.SHB("my computer", "linux", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        block.EPB( idb0, input:getData(1),  timestamp ),
    }
end


return test
