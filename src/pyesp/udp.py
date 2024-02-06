#import pyesp.ip6_header 
import ipaddress

from construct import *
from construct.lib import *


UserDatagram = Struct(
  "src_port" / Int16ub,
  "dst_port" / Int16ub,
  "length" / ExprAdapter(Int16ub,
        encoder = lambda obj,ctx: obj + 8,
        decoder = lambda obj,ctx: obj - 8,
    ),
  "checksum" / Bytes(2),
  "data" / GreedyBytes
)

Ipv6Address = ExprAdapter(Byte[16],
    decoder = lambda obj,ctx: ipaddress.IPv6Address( obj ).compressed,
    encoder = lambda obj,ctx: ipaddress.IPv6Address( obj ).packed,
)


UDPseudoHeader = Struct(
    "src_ip" / Ipv6Address,
    "dst_ip" / Ipv6Address,
    "zero" / Const( b'\x00' ),
#    "protocol" / Const( ip6_header.ProtocolType( 'UDP' ) ),
    "protocol" / Const( b'\x01\x01'),
    "length" / BitsInteger(2)
) 

class UDP:

  def __init__( self, 
                src_port=0,
                dst_port=0,
                length=None, 
                checksum=None,
                data=b'', 
                packed=None, 
                src_ip=None, 
                dst_ip=None ):
    if packed != None:
      self.unpack( packed, src_ip=src_ip, dst_ip=dst_ip )
    else:
      self.src_port = src_port
      self.dst_port = dst_port
      self.length = length
      self.checksum = checksum
      self.data = data
      self.src_ip = src_ip
      self.dst_ip = dst_ip
#  def get_ip( self, ip ):
#    if isinstance( ipaddress.IPv6Address ) is False:
#      ip = ipaddress.IPv6Address( ip )    
#    return ip

  def compute_length_from_data( self ):
    return len( self.data ) + 8

  def compute_checksum( self, src_ip=None, dst_ip=None ) -> bytes:
    """ compute the checksum 
    See: https://github.com/houluy/UDP/blob/master/udp.py
    """
    ## When ip addresses are provided to compute the checksum, 
    ## We add the ip addresses as part of the UDP parameters 
    if src_ip is not None and dst_ip is not None:
      self.src_ip = src_ip
      self.dst_ip = dst_ip 

    ## when src_ip or dst_ip ar enot directly provided, 
    ## we check if src_ip/dst_ip have not been defined 
    ## in the object. 
    if src_ip is None or dst_ip is None:
      src_ip = self.src_ip 
      dst_ip = self.dst_ip

    if src_ip is None or dst_ip is None:
      return b'\x00\x00'

    pseudo_header = UDPseudoHeader.build( \
      { "src_ip" : src_ip, 
        "dst_ip" : dst_ip, 
        "length" : self.compute_length_from_data() } )

    if ( len( pseudo_header ) % 2):
        pseudo_header += b'\x00'

    self.checksum = 0
    for i in range(0, len( pseudo_header ), 2):
        w = (pseudo_header[i] << 8) + (pseudo_header[i + 1])
        self.checksum += w

    self.checksum = (self.checksum >> 16) + (self.checksum & 0xFFFF)
    self.checksum = ~self.checksum & 0xFFFF
    return self.checksum

  def pack( self, src_ip=None, dst_ip=None ):
    """build teh UDP datagram

    providing src_ip and dst_ip forces the computation of checksum.
    Otherwise, when src_ip or dst_ip ar enot provided, the value 
    self.checksum is considered unless it is set to None, in which
    case, it is replaced by zero. 
    """
    if isinstance( self.data, bytes ):
      data = self.data
    else: 
      data = data.pack( )

    ## checksum is computed whenever possible with IP addresses.
    ## When ip addresses are not provided and self.checksum 
    ## is not \x00\x00 we provide that value.
    if ( src_ip is None or dst_ip is None ) and \
       ( self.src_ip is None or self.dst_ip is None ) and \
       self.checksum is not None:
      checksum = self.checksum
    else: 
      checksum = self.compute_checksum( src_ip=src_ip, dst_ip=dst_ip )
    return UserDatagram.build( \
             { "src_port" : self.src_port, 
               "dst_port" : self.dst_port,
               "length" :  self.compute_length_from_data(),
               "checksum" : checksum, 
               "data" : data } )

  def unpack(self, udp:bytes, src_ip=None, dst_ip=None ):
    udp = UserDatagram.parse( udp ) 
    self.src_port = udp[ 'src_port' ]
    self.dst_port = udp[ 'dst_port' ]
    self.length = udp[ 'length' ]
    self.checksum = udp[ 'checksum' ]
    self.data = udp[ 'data' ]
    self.src_ip = src_ip
    self.dst_ip = dst_ip
    if src_ip is not None and dst_ip is not None and self.checksum != b'\x00\x00':
      expected_checksum = self.compute_checksum( src_ip=src_ip, dst_ip=dst_ip )
      if self.checksum != expected_checksum :
        raise ValueError (f"Invalid checksum. Received {self.checksum} "\
                f"/ Expecting {expected_checksum}" )
    return self.data

  def show( self ):
    """Display the UDP packet 
    """
    print( "## UDP ##" )
    print( UserDatagram.parse( self.pack( ) ) )
    print( "binary:" )
    print( self.pack() ) 
    print( "\n" )
