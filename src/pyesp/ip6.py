import secrets
import pyesp.h6
#import pyesp.h6_x

import binascii
from construct import *
from construct.lib import *

class IP6:

  def __init__( self,
    header=pyesp.h6.H6(),
    ext_header_list=[],
    payload=b'', 
    packed=None ):

    if packed is not None:
      self.unpack( packed )
    else:   
      self.header = header
      self.ext_header_list = ext_header_list
      self.payload = payload
    self.header_type = 'IPv6'

  def pack( self, ):
    """ consolidates the extensions and output the corresponding bytes """ 
    pack_bytes = b''
    if isinstance( self.payload, bytes ):
      if self.payload == b'':
        next_header_type='IPv6NoNxt'
      else:
        ## there is no much we can do here
        ## the type must be filled in the header
        pass
      pack_bytes = self.payload
    else:
      next_header_type=self.payload.header_type
      ## UDP is special as ip addresses are considered in
      ## the checksum
      if next_header_type == 'UDP':
        pack_bytes = self.payload.pack(\
                src_ip=self.header.src_ip,\
                dst_ip=self.header.dst_ip )
      else:
        pack_bytes = self.payload.pack()
        
    for hdr_ext in reversed( self.ext_header_list ):
      hdr_ext.next_header = next_header_type
      next_header_type = hdr_ext.header_type
      pack_bytes = hdr_ext.pack() + pack_bytes

    self.header.payload_length = len( pack_bytes )
    self.header.next_header = next_header_type
    pack_bytes = self.header.pack() + pack_bytes
    return pack_bytes




  def unpack( self, bytes_ip6:bytes ):
    if isinstance( bytes_ip6, bytes) is False:
      raise ValueError( f"expecting bytes, recievd {type(ip6)}" )
    if len( bytes_ip6 ) < 40 :
      raise ValueError( f"Not enough bytes ({len( ip6 )}. "\
                        f"Expectiong at least 40" )
    byte_pointer = 0
    self.header = pyesp.h6.H6( packed=bytes_ip6[ byte_pointer:40 ] )
    byte_pointer = 40
    next_header = self.header.next_header
    remaining_length = self.header.payload_length
    if remaining_length == 0:
      self.payload = b''
    self.ext_header_list = []
    while byte_pointer < 40 + remaining_length :
      ## IP6 Header Extension
      if next_header in [ 'HOPOPT', 'IPv6Route', 'IPv6Frag', 'ESP',\
                          'AH', 'IPv6Opts', 'MobilityHeader', 'HIP',\
                          'Shim6', 'EXP1', 'EXP2' ]:  
        if next_header == "ESP" :
          length = remaining_length
        elif next_header == "AH" :
          length = 4 * ( bytes_ip6[ byte_pointer + 1 ] + 2 )
        else:
          length = 8 * ( bytes_ip6[ byte_pointer + 1 ] + 1 )

        packed = bytes_ip6[ byte_pointer: byte_pointer + length ]

        if next_header == 'HOPOPT' :
          ext = None
        elif next_header == 'IPv6Route':  
          ext = None  
        elif next_header == 'ESP' :
          ext = pyesp.h6_esp.ESP( packed=packed )
          ## in the case of ESP the payload is assumed to be b''
          ## we need this to initialize self.payload and remain
          ## consistent
          self.payload = b''
          #unpack_clear_text_esp_payload ) 
        elif next_header == 'AH' :
          ext = None
        else: 
          ext = pyesp.h6_x.H6X( packed=packed )
        self.ext_header_list.append( ext )
        next_header = ext.next_header
        byte_pointer += byte_pointer + length 
      else:
        packed = bytes_ip6[ byte_pointer: ]

        if next_header == 'UDP':
          payload = pyesp.udp.UDP( packed=packed )
        elif next_header == 'SCHC':
          payload = pyesp.schc.SCHC( packed=packed )    
        else: 
          payload = packed
        self.payload = payload  
        break

  def contains( self, header_type:str )-> bool:
    """ determine is an extension or a certain payload type is present 
    """

    for hx in self.ext_header_list:
      if hx.header_type == header_type : 
        return True
    if isinstance( self.payload, bytes ) == False:
      if self.payload.header_type == header_type:
        return True
    return False
      

  def show( self ):
    """Display the IP6 packet 
    """
    ## to synchronize various fields such as length, next_header
    self.unpack( self.pack() )
    print( "## IP6 ##" )
    self.header.show()
    if len( self.ext_header_list ) != 0:
      for h_ext in self.ext_header_list:
        h_ext.show()
    if self.payload == b'': 
      pass
    else: 
      self.payload.show()    
              
