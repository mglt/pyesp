import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(0, '../../openschc/src/')
sys.path.insert(0, '../src/' )


import binascii

import pyesp
import pyesp.h6
import pyesp.h6_x
import pyesp.h6_esp
import pyesp.udp
import pyesp.ip6
import pyesp.sa
import pyesp.ipsec

#from binascii import hexlify

## This script provides a simple example where ESP is used to
## encrypt some application data between Alice and Bob


if __name__ == "__main__":
  if True:
      print( f"\n\n---- SCHC IP6/ESP/UDP in Tunnel mode\n\n" ) 
      
      
  try:
      payload_size = int(input("Enter the payload size in bytes: "))
  except ValueError:
      print("Invalid input. Please enter a valid integer.")
      sys.exit(1)
      
  payload_size = payload_size #example = 10
      
 if True:
      print( f"\n\n---- SCHC IP6/ESP/UDP in Tunnel mode\n\n" ) 
      
  alice_ip = '2001:db8::1000'
  sa = pyesp.sa.SA()
  ## configuring EHC
  sa.ehc_pre_esp = 'ipv6-sol-bi-fl-esp-mglt.json'
  sa.ehc_clear_text_esp = 'ipv6-sol-bi-fl-esp-mglt.json'
  sa.ehc_esp = 'ipv6-sol-bi-fl-esp-mglt.json'
  ## rules requires the following match
  sa.spi= (5).to_bytes( 4, byteorder='big')
  sa.sn=1
  bob_ip = 'ff02::5678'
  data =  os.urandom(payload_size) #b'confidential udp data'
  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
          data=data, src_ip=alice_ip, dst_ip=bob_ip )
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6, payload=alice_udp )
  print( "\n#### Showing Clear Text IP6" ) 
  alice_ip6.show()
  ## we keep track of the binary format as with Transport mode the 
  ## ip6 packet is updated to form an ipsec packet. 
  alice_ip6_pack = alice_ip6.pack() #pack ip6 and udp headers and ESP enc
  alice_ipsec = pyesp.ipsec.IPsec()
  alice_ipsec_ip6 = alice_ipsec.outbound_esp( alice_ip6, sa )
  print( "\n#### Showing SENT IPsec tunneled IP6 (in clear text mode)" ) 
  alice_ipsec_ip6.show()

  bob_ipsec_ip6 = pyesp.ip6.IP6( packed=alice_ipsec_ip6.pack() )
  print( "\n#### Showing RECEIVED IPsec tunneled IP6 (no SA so encrypted ESP )" ) 
  bob_ipsec_ip6.show()
  print( "\n#### Showing RECEIVED IPsec decrypted" ) 
  bob_ipsec = pyesp.ipsec.IPsec()
  bob_ip6 = bob_ipsec.inbound_esp( bob_ipsec_ip6, sa )
  if isinstance( bob_ip6, pyesp.ip6.IP6 ) == False:
    raise ValueError( f"ESP decapsulation is expected to provide an IP6 packet. Received {type( bob_ip6 )}" )  
    pass  
  bob_ip6.show()
  if alice_ip6_pack != bob_ip6.pack():
    print( "UDP message sent by Alice:" )  
    alice_udp.show()   
    print( "UDP message received by Bob:" )  
    bob_ip6.payload.show()
    raise ValueError( "alice and bob packets are expected to be equal" )
    
