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


if True:
  print( f"\n\n# ESP/UDP\n\n" ) 
  alice_ip = '2001:db8::1000'
  bob_ip = 'ff02::5678'
  sa = pyesp.sa.SA()
  
  
  
  
  data = b'confidential udp data'
  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
          data=data, src_ip=alice_ip, dst_ip=bob_ip )
  alice_udp.show()
  
  alice_esp = pyesp.h6_esp.ESP(sa=sa, data=alice_udp )
  #alice_esp_pkt = alice_esp.pack( alice_udp.pack( ), debug=True )
  alice_esp.show()
  print( "-- Alice ESP packet")
  
  print( "-- Bob receives the packet" )
  bob_esp = pyesp.h6_esp.ESP(sa=sa)
  bob_inner = bob_esp.unpack( alice_esp.pack() )
  bob_udp = pyesp.udp.UDP( packed=bob_inner, src_ip=alice_ip, dst_ip=bob_ip )
  bob_udp.show()
  #bob_data = bob_udp.parse( inner )
  print( f"-- Bob's data: {bob_udp.data}" )


if True:
  print( f"\n\n---- IPv6 Header\n\n" ) 
  alice_ip = '2001:db8::1000'
  bob_ip = 'ff02::5678'
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
#  alice_ip6 = pyesp.ip6.IP6( header=ip6h )
  alice_h6.show()

  print( f"\n\n---- Empty IPv6 Packet\n\n" ) 
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6 )
  alice_ip6.show()


if True:
  alice_ip = '2001:db8::1000'
  bob_ip = 'ff02::5678'

  print( f"\n\n---- Empty IPv6 Packet (pack/unpack)\n\n" ) 
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6 )
  alice_ip6.show()

  print( f"\n\n---- unpacking at instantiation\n\n" ) 
  bob_ip6 = pyesp.ip6.IP6( packed=alice_ip6.pack() )
  bob_ip6.show()
  if alice_ip6.pack() != bob_ip6.pack():
    raise ValueError( "alice and bob packets are expected to be equal" )    

  print( f"\n\n---- unpacking with default IP6 instantiation\n\n" ) 
  bob_ip6 = pyesp.ip6.IP6( )
  bob_ip6.unpack( alice_ip6.pack() )
  bob_ip6.show()
  if alice_ip6.pack() != bob_ip6.pack():
    raise ValueError( "alice and bob packets are expected to be equal" )    

if True:   
  print( f"\n\n---- IP6/UDP\n\n" ) 
  alice_ip = '2001:db8::1000'
  bob_ip = 'ff02::5678'
  data = b'confidential udp data'
  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
          data=data, src_ip=alice_ip, dst_ip=bob_ip )
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6, payload=alice_udp )
  alice_ip6.show()

  bob_ip6 = pyesp.ip6.IP6( packed=alice_ip6.pack() )
  bob_ip6.show()
  if alice_ip6.pack() != bob_ip6.pack():
    raise ValueError( "alice and bob packets are expected to be equal" )    
 
if True:
  print( f"\n\n---- Empty IP6 in Tunnel mode\n\n" ) 
  alice_ip = '2001:db8::1000'
  sa = pyesp.sa.SA()

  bob_ip = 'ff02::5678'
#  data = b'confidential udp data'
#  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
#          data=data, src_ip=alice_ip, dst_ip=bob_ip )
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6 )
  print( "\n#### Showing Clear Text IP6" ) 
  alice_ip6.show()
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
  bob_ip6.show()
  if alice_ip6.pack() != bob_ip6.pack():
    raise ValueError( "alice and bob packets are expected to be equal" )    

if True:
  print( f"\n\n---- Empty IP6 in Transport mode\n\n" ) 
  alice_ip = '2001:db8::1000'
  sa = pyesp.sa.SA()
  sa.mode = 'transport'
  bob_ip = 'ff02::5678'
#  data = b'confidential udp data'
#  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
#          data=data, src_ip=alice_ip, dst_ip=bob_ip )
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6 )
  print( "\n#### Showing Clear Text IP6" ) 
  alice_ip6.show()
  ## we keep track of the binary format as with Transport mode the 
  ## ip6 packet is updated to form an ipsec packet. 
  alice_ip6_pack = alice_ip6.pack()
  alice_ipsec = pyesp.ipsec.IPsec()
  alice_ipsec_ip6 = alice_ipsec.outbound_esp( alice_ip6, sa )
  print( "\n#### Showing SENT IPsec Transport IP6 (in clear text mode)" ) 
  alice_ipsec_ip6.show()
  
  bob_ipsec_ip6 = pyesp.ip6.IP6( packed=alice_ipsec_ip6.pack() )
  print( "\n#### Showing RECEIVED IPsec Transport IP6 (no SA so encrypted ESP )" ) 
  bob_ipsec_ip6.show()
  print( "\n#### Showing RECEIVED IPsec decrypted" ) 
  bob_ipsec = pyesp.ipsec.IPsec()
  bob_ip6 = bob_ipsec.inbound_esp( bob_ipsec_ip6, sa )
  if isinstance( bob_ip6, pyesp.ip6.IP6 ) == False:
    raise ValueError( f"ESP decapsulation is expected to provide an IP6 packet. Received {type( bob_ip6 )}" )    
  bob_ip6.show()
  if alice_ip6_pack != bob_ip6.pack():
    print("alice:")
    print( binascii.hexlify( alice_ip6.pack(), sep=' ' ) )
    print("bob:")
    print( binascii.hexlify( bob_ip6.pack(), sep=' ' ) )
    raise ValueError( "alice and bob packets are expected to be equal" )    



if True:
  print( f"\n\n---- IP6/ESP/UDP in Transport mode\n\n" ) 
  alice_ip = '2001:db8::1000'
  sa = pyesp.sa.SA()
  sa.mode = 'transport'

  bob_ip = 'ff02::5678'
  data = b'confidential udp data'
  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
          data=data, src_ip=alice_ip, dst_ip=bob_ip )
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6, payload=alice_udp )
  print( "\n#### Showing Clear Text IP6" ) 
  alice_ip6.show()
  ## we keep track of the binary format as with Transport mode the 
  ## ip6 packet is updated to form an ipsec packet. 
  alice_ip6_pack = alice_ip6.pack()
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
  bob_ip6.show()
  if alice_ip6_pack != bob_ip6.pack():
    raise ValueError( "alice and bob packets are expected to be equal" )   

if True:
  print( f"\n\n---- IP6/ESP/UDP in Tunnel mode\n\n" ) 
  alice_ip = '2001:db8::1000'
  sa = pyesp.sa.SA()

  bob_ip = 'ff02::5678'
  data = b'confidential udp data'
  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
          data=data, src_ip=alice_ip, dst_ip=bob_ip )
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6, payload=alice_udp )
  print( "\n#### Showing Clear Text IP6" ) 
  alice_ip6.show()
  ## we keep track of the binary format as with Transport mode the 
  ## ip6 packet is updated to form an ipsec packet. 
  alice_ip6_pack = alice_ip6.pack()
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
  bob_ip6.show()
  if alice_ip6_pack != bob_ip6.pack():
    raise ValueError( "alice and bob packets are expected to be equal" )   



if True:
  print( f"\n\n---- SCHC IP6/ESP/UDP in Tunnel mode\n\n" ) 
      
  alice_ip = '2001:db8::1000'
  sa = pyesp.sa.SA()
  ## configuring EHC
  sa.ehc_pre_esp = 'ipv6-sol-bi-fl-esp-mglt.json'
  sa.ehc_clear_text_esp = None
  sa.ehc_esp = 'ipv6-sol-bi-fl-esp-mglt.json'
  ## rules requires the following match
  sa.spi= (5).to_bytes( 4, byteorder='big')
  sa.sn=1
  bob_ip = 'ff02::5678'
  data = b'confidential udp data'
  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
          data=data, src_ip=alice_ip, dst_ip=bob_ip )
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip )  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6, payload=alice_udp )
  print( "\n#### Showing Clear Text IP6" ) 
  alice_ip6.show()
  ## we keep track of the binary format as with Transport mode the 
  ## ip6 packet is updated to form an ipsec packet. 
  alice_ip6_pack = alice_ip6.pack()
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
  bob_ip6.show()
  if alice_ip6_pack != bob_ip6.pack():
    print( "UDP message sent by Alice:" )  
    alice_udp.show()   
    print( "UDP message received by Bob:" )  
    bob_ip6.payload.show()
    raise ValueError( "alice and bob packets are expected to be equal" )   


