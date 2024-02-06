import sys
sys.path.insert(0, '../src/' )

import pyesp
import pyesp.sa
import pyesp.esp
#import pyesp.ip6_header
import pyesp.udp

#from binascii import hexlify

## This script provides a simple example where ESP is used to
## encrypt some application data between Alice and Bob


alice_ip = '2001:db8::1000'
bob_ip = 'ff02::5678'
sa = pyesp.sa.SA()


alice_esp = pyesp.esp.ESP(sa)
bob_esp = pyesp.esp.ESP(sa)


data = b'confidential udp data'
alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
        data=data, src_ip=alice_ip, dst_ip=bob_ip )
alice_udp.show()


alice_esp_pkt = alice_esp.pack( alice_udp.pack( ), debug=True )
print( "-- Alice ESP packet")

print( "-- Bob receives the packet" )
bob_inner = bob_esp.unpack( alice_esp_pkt, debug=True )
bob_udp = pyesp.udp.UDP( packed=bob_inner, src_ip=alice_ip, dst_ip=bob_ip )
bob_udp.show()
#bob_data = bob_udp.parse( inner )
print( f"-- Bob's data: {bob_udp.data}" )
