import sys
sys.path.insert(0, '../src/' )

import pyesp
import pyesp.sa
import pyesp.esp
from binascii import hexlify

## This script provides a simple example where ESP is used to
## encrypt some application data between Alice and Bob


sa = pyesp.sa.SA()
alice_esp = pyesp.esp.ESP(sa)
bob_esp = pyesp.esp.ESP(sa)

data = b'inner_ip6_packet'

alice_esp_pkt = alice_esp.pack( data, debug=True )
print( "-- Alice ESP packet")

print( "-- Bob receives the packet" )
bob_data = bob_esp.unpack( alice_esp_pkt, debug=True )
print( f"-- Bob's data: {bob_data}" )
