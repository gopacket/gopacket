-- prevent wireshark loading this file as a plugin
if not _G['pcapng_test_gen'] then return end


local block = require "blocks"
local input = require "input"


local test = {
    category    = 'difficult',
    description = "idb with a resolution of one second",
}


local timestamp = UInt64(0x5a8c0dc0, 0x00000000)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 0, "eth0")
                    :addOption( block.OptionFormat ('if_tsresol', "B", 0x00) )

    self.blocks = {
        block.SHB("my computer", "linux", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        block.EPB( idb0, input:getData(1),  timestamp ),
    }
end


return test
