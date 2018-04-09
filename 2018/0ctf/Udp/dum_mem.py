import idaapi

start_address = 0x6020E0
data_length = 4000*4000*8

data = idaapi.dbg_read_memory(start_address, data_length)
fp = open('dump.dex', 'wb')
fp.write(data)
fp.close()

