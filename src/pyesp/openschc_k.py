#!/usr/bin/env python3
from scapy.all import *


import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../openschc/src/')


import binascii
import typing
import compr_core
import compr_parser
import gen_rulemanager
import gen_bitarray
## import all openschc symbols
from gen_parameters import *

def show( v_name, v ):
  t = type( v )
  if t in [ bytes, bytearray ]:
    v = binascii.hexlify( v, sep=' ' )
  print (f"{v_name} [{type(v)}]: {v}\n---\n")



#type Parsed = tuple[ dict, bytes, None]

class Kompressor:

  def __init__( self, compression_rule_file,\
          direction=T_DIR_DW, 
          verbose=True ):
    self.RM = gen_rulemanager.RuleManager()
    self.RM.Add( file=compression_rule_file )
    self.direction = direction
    self.verbose = True
    self.compressor = compr_core.Compressor()
    self.decompressor = compr_core.Decompressor()
    ## Parser / UnParser are implemneted by openSCHC
    self.parser = compr_parser.Parser()
    self.unparser = compr_parser.Unparser()
    self.next_header = None

#  def parse( self, byte_packet:bytes ) -> Parsed:
  def parse( self, byte_packet:bytes ):
    """ parses the byte packets into SCHC structure

    The SCHC structure is needed to 1) find the rule and 2) 
    build the SCHC packet
    """
    pass

  def schc( self, byte_packet ) -> bytes:

    parsed_packet = self.parse( byte_packet )
    if parsed_packet[0] is None:
      raise ValueError( f"Unexpected parsed_packet[0]: {parsed_packet}")  
      return parsed_packet[1]

    packet_rule = self.RM.FindRuleFromPacket(\
            pkt=parsed_packet[0], # header 
            direction=self.direction, 
            failed_field=True)
    if not packet_rule:
      raise ValueError( f"Unexpected packet_rule: {packet_rule}")  
      return parsed_packet[1]
    byte_next_header = int.to_bytes( self.next_header, 1, byteorder='big' )  
    parsed_SCHC_hdr = { ("SCHC.NXT", 1): [ byte_next_header, 8] }
    if self.verbose is True:
      show( 'parsed_SCHC_hdr', parsed_SCHC_hdr )
    SCHC_hdr_rule = self.RM.FindRuleFromPacket(
                            pkt=parsed_SCHC_hdr,
                            direction=self.direction,
                            failed_field=True,
                            schc_header=True
    )
    if self.verbose is True:
      show( 'SCHC_hdr_rule', SCHC_hdr_rule )
    ## compressor outputs a an object of type 
    ## gen_bitarray.BitBuffer
    SCHC_hdr = self.compressor.compress(rule=SCHC_hdr_rule,
                                 parsed_packet=parsed_SCHC_hdr,
                                 data=b'',
                                 direction=self.direction,
                                 verbose=True)    
    if self.verbose is True:
      show( 'SCHC_hdr', SCHC_hdr )
    SCHC_packet = self.compressor.compress(rule=packet_rule,
                                 parsed_packet=parsed_packet[0],
                                 data= parsed_packet[1],
                                 direction=self.direction,
                                 verbose=True,
                                 append=SCHC_hdr) # append add to the buffer

    if self.verbose is True:
      show( 'SCHC_packet', SCHC_packet )
    return SCHC_packet.get_content() 
  
  def unschc( self, byte_schc_packet:bytes ):
    schc = gen_bitarray.BitBuffer( byte_schc_packet )
    SCHC_header_rule = self.RM.FindSCHCHeaderRule()
    if self.verbose is True:
      show( f"SCHC_header_rule", SCHC_header_rule )
    SCHC_header = self.decompressor.decompress(rule=SCHC_header_rule, 
            schc=schc, 
            direction=self.direction, 
            schc_header=True)
    show( "SCHC_header", SCHC_header )
    schc_payload = gen_bitarray.BitBuffer( schc.get_remaining_content() )
    if self.verbose is True:
      show( "schc_payload", schc_payload ) # [{type(rData)}]: {rData}" )
    schc_payload_rule = self.RM.FindRuleFromSCHCpacket(schc=schc_payload ) 
    if self.verbose is True:
      show( "schc_payload_rule", schc_payload_rule )         
    payload_fields = self.decompressor.decompress(rule=schc_payload_rule,
            schc=schc_payload, 
            direction=self.direction, schc_header=False)
    if self.verbose is True:
      show( "payload_fields", payload_fields )

    payload = schc_payload.get_remaining_content()
    return self.unparse( payload, payload_fields )

  


class UDPKompressor( Kompressor ):

  def __init__( self, compression_rule_file,\
          direction=T_DIR_DW, 
          verbose=True ):
    super().__init__( compression_rule_file,\
                      direction=T_DIR_DW, 
                      verbose=True )   
    self.next_header = 17 # or \x11

#  def parse( self, byte_packet:bytes ) -> Parsed:
  def parse( self, byte_packet:bytes ) :

    parsed_udp =  self.parser.parse (byte_packet, 
                         self.direction, 
                         layers=["UDP"],
                         start="UDP")
    if self.verbose is True:  
      show( 'parsed_udp', parsed_udp )
    return parsed_udp

  def unparse( self, payload:bytes,  payload_fields:dict )->bytes:
    show( 'unparse-udp', payload )  
    if ('UDP.DEV_PORT', 1) in payload_fields:
      port_src = int.from_bytes( payload_fields[ ('UDP.DEV_PORT', 1) ][0], byteorder="big" )
    else:
      port_src = int.from_bytes( payload[ : 2 ] )
      payload = payload[ 2 : ]
    if ('UDP.APP_PORT', 1) in payload_fields:
      port_dst = int.from_bytes( payload_fields[('UDP.APP_PORT', 1) ][0], byteorder="big" )
    else:
      port_dst = int.from_bytes( payload[ : 2 ] )
      payload = payload[ 2 : ]
    if ('UDP.LEN', 1) in payload_fields:
      udp_len = None  
    else: 
      udp_len = int.from_bytes( payload[ : 2 ] )
      payload = payload[ 2 : ]
        
    if ('UDP.CKSUM', 1) in payload_fields:
      checksum = 0 
    else: 
      checksum = int.from_bytes( payload[ : 2 ] )
      payload = payload[ 2 : ]
              
    udp = bytes( UDP( sport=port_src, 
               dport= port_dst, 
               len=len( payload ) + 8, 
               chksum=0 )/Raw(load=payload) )

    if self.verbose is True:
      show( 'udp', udp )
    return udp


class EncryptedESPKompressor( Kompressor ):
  def __init__( self, compression_rule_file,\
          direction=T_DIR_DW, 
          verbose=True ):
    super().__init__( compression_rule_file,\
                      direction=T_DIR_DW, 
                      verbose=True )  
    self.next_header = 50 # \x32

  def parse( self, byte_packet:bytes ) :
    parsed_esp =  self.parser.parse (byte_packet, 
                         direction, 
                         layers=["ESP"],
                         start="ESP")
    if self.verbose is True:  
      show( 'parsed_esp', parsed_esp )
    return parsed_esp

  def unparse( self,payload:bytes,  payload_fields:dict )->bytes:
    if ('ESP.SPI', 1) in payload_fields:
      spi = int.from_bytes( payload_fields[('ESP.SPI', 1)][0], byteorder="big" )
    else: 
      spi = int.from_bytes( payload[ : 4],  "big" )
      payload =  payload[ 4 :]        
    if  ('ESP.SEQ', 1) in payload_fields:
      sn = int.from_bytes( payload_fields[('ESP.SEQ', 1)][0], byteorder="big" )
    else:   
      sn = int.from_bytes( payload[ : 4],  "big" )
#    encrypted_data =  payload[ 4 :]
    esp = bytes( ESP(spi=spi, seq=sn, data=payload ) )
 
    if self.verbose is True:
      show( 'encrypted_esp', esp )

    return esp


