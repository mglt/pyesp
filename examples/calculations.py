import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(0, '../../openschc/src/')
sys.path.insert(0, '../src/' )
#print(sys.path)
import binascii
import math 

import pyesp
import pyesp.h6
import pyesp.h6_x
import pyesp.h6_esp
import pyesp.udp
import pyesp.ip6
import pyesp.sa
import pyesp.ipsec
import os
#from binascii import hexlify

## This script provides a simple example where ESP is used to
## encrypt some application data between Alice and Bob
import pyesp.ip6
import pyesp.h6_esp
import pyesp.sa
import pyesp.ipsec
import pyesp.udp
comp = 50
print("bytecomp",comp) 

 
 
def compressed_packet(payload_size):
 

      
      
 #if True:
 # print( f"\n\n---- SCHC IP6/ESP/UDP in Tunnel mode\n\n" ) 
      
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
  data =  os.urandom(payload_size) #b'confidential udp data'
  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
          data=data, src_ip=alice_ip, dst_ip=bob_ip )
          
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip ) #ipv6 header
  print( "\n#### Showing I_IP6 header", len(alice_h6.pack())) # = 
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6, payload=alice_udp )
  print( "\n#### Showing [I_IP6 header[UDP header[data]]]", len(alice_ip6.pack())) # size

  ## we keep track of the binary format as with Transport mode the 
  ## ip6 packet is updated to form an ipsec packet. 
  alice_ip6_pack = alice_ip6.pack()
  alice_ipsec = pyesp.ipsec.IPsec()
  #print( "\n#### Showing [ESP[[I_IP6 header[UDP header[data]]]]ESP]", len(alice_ip6_pack)) # = + size
    
    
  alice_ipsec_ip6 = alice_ipsec.outbound_esp( alice_ip6, sa ) #outbound means esp tunnel mode encapsulation
  print( "\n#### Showing [O-IPv6 header [ESP[[I_IP6 header[UDP header[data]]]]ESP]]", len(alice_ipsec_ip6.pack())) # =  + size
  compressed_size = payload_size + 63
  
  return compressed_size
  

def fullpacket(payload_size):
 
 #if True:
  print( f"\n\n---- SCHC IP6/ESP/UDP in Tunnel mode\n\n" ) 
      
      

      
      
 #if True:
 # print( f"\n\n---- SCHC IP6/ESP/UDP in Tunnel mode\n\n" ) 
      
  alice_ip = '2001:db8::1000'
  sa = pyesp.sa.SA()
  ## configuring EHC
  sa.ehc_pre_esp = None #'ipv6-sol-bi-fl-esp-mglt.json'
  sa.ehc_clear_text_esp = None
  sa.ehc_esp = None #'ipv6-sol-bi-fl-esp-mglt.json'
  ## rules requires the following match
  sa.spi= (5).to_bytes( 4, byteorder='big')
  sa.sn=1
  bob_ip = 'ff02::5678'
  data =  os.urandom(payload_size) #b'confidential udp data'
  alice_udp = pyesp.udp.UDP( src_port=123, dst_port=4567,
          data=data, src_ip=alice_ip, dst_ip=bob_ip )
          
  alice_h6 = pyesp.h6.H6( src_ip=alice_ip, dst_ip=bob_ip ) #ipv6 header
  print( "\n#### Showing I_IP6 header", len(alice_h6.pack())) # = 40
  
  alice_ip6 = pyesp.ip6.IP6( header=alice_h6, payload=alice_udp )
  print( "\n#### Showing [I_IP6 header[UDP header[data]]]", len(alice_ip6.pack())) # = 40 + 8 + size

  ## we keep track of the binary format as with Transport mode the 
  ## ip6 packet is updated to form an ipsec packet. 
  alice_ip6_pack = alice_ip6.pack()
  alice_ipsec = pyesp.ipsec.IPsec()
  #print( "\n#### Showing [ESP[[I_IP6 header[UDP header[data]]]]ESP]", len(alice_ip6_pack)) # = 40 + 8 + 19 + size
    
    
  alice_ipsec_ip6 = alice_ipsec.outbound_esp( alice_ip6, sa )
  print( "\n#### Showing [O-IPv6 header [ESP[[I_IP6 header[UDP header[data]]]]ESP]]", len(alice_ipsec_ip6.pack())) # = 40 + 8 + 19 + 40 + size
  
  full_size = len(alice_ipsec_ip6.pack()) + 6 #6 bytes is required more in esp header

  
  return full_size
    
    
    
if __name__ == "__main__":

   #if True:
  print( f"\n\n---- SCHC IP6/ESP/UDP in Tunnel mode\n\n" )

  # Given payload sizes and corresponding percentages
  
  #payload_sizes = [73, 132, 221, 413, 968, 1491]
  #weights = [3.4, 17.9, 16.6, 16.5, 12.6, 33.2]
  
  #payload_sizes = [73, 133, 236, 485, 1027, 1385]
  #weights = [1.3, 5.1, 29.0, 2.7, 12.9, 49.0]
  
  #payload_sizes = [68, 124, 170, 1022, 1406]
  #weights = [0.2, 5.9, 47.0, 23.2, 23.7]
  
  
  payload_sizes = [64, 129, 190, 570, 1022]
  weights = [4.9, 76.5, 6.3, 3.5, 8.9]
 

  # Initialize sum variables for reduction, ratio, and weights
  total_weighted_reduction = 0
  total_weighted_ratio = 0
  total_weights = sum(weights)

  for i, payload_size in enumerate(payload_sizes):
    print(f"\nCalculating for payload size: {payload_size} bytes")

    # Calculate full size and compressed size
    full_size = fullpacket(payload_size)
    compressed_size = compressed_packet(payload_size)

    # Calculate reduction and ratio
    reduction = 100 * ((full_size) - (compressed_size)) / (full_size)
    ratio = 100 * (compressed_size) / full_size

    print(f"Full packet [esp[ip[udp]]] no schc =: {full_size}")
    print(f"Compressed packet [schc[esp[schc[ip[schc[udp]]]  =: {compressed_size}")
    print(f"Reduction is: {reduction}")
    print(f"Ratio is: {ratio}")

    # Multiply reduction and ratio by their corresponding weight and accumulate
    total_weighted_reduction += reduction * weights[i]
    total_weighted_ratio += ratio * weights[i]

  # Calculate the average weighted reduction and ratio
  average_weighted_reduction = total_weighted_reduction / total_weights
  average_weighted_ratio = total_weighted_ratio / total_weights

  # Output the results
  print(f"\nWeighted average reduction across all payload sizes is: {average_weighted_reduction:.2f}%")
  print(f"Weighted average ratio across all payload sizes is: {average_weighted_ratio:.2f}%")
  
    
  """    
  try:
      payload_size = int(input("Enter the payload size in bytes: "))
  except ValueError:
      print("Invalid input. Please enter a valid integer.")
      sys.exit(1)

  full_size = fullpacket(payload_size)
  compressed_size = compressed_packet(payload_size)
  print("Full packet [esp[ip[udp]]] no schc =:", full_size)
  print("Compressed packet [schc[esp[schc[ip[schc[udp]]]  =:", compressed_size)
  reduction = 100 * (full_size - compressed_size)/full_size
  ratio =  100 *  (compressed_size)/full_size
  print("reduction is:", reduction)
  print("ratio is:", ratio)
"""

