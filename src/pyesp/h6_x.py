import secrets 

import pyesp.h6
import pyesp.h6_route 
import pyesp.h6_esp

from construct import *
from construct.lib import *


## The code points are also listed in the protocol type. 
## This list is only to distinguish between Extension header and Protocol
## We need to check if that is needed.

ExtHeaderType = Enum( BytesInteger(1),
  HOPOPT = 0,
#  IPv6-Route = 43, 
  IPv6Route = 43, 
#  IPv6-Frag = 44, 
  IPv6Frag = 44, 
  ESP = 50, 
  AH = 51, 
#  IPv6-Opts = 60, 
  IPv6Opts = 60, 
#  Mobility Header = 135,
  MobilityHeader = 135,
  HIP = 139,
  Shim6 = 140,
  EXP1 = 253,
  EXP2 = 254,
  )

### IPv6 Extention Header

GenericExtentionHeader = Struct(
  "next_header" / pyesp.h6.NextHeaderType,
  "header_len" / ExprAdapter(Int8ub,
        encoder = lambda obj,ctx: obj / 8 - 8,
        decoder = lambda obj,ctx: obj * 8 + 8,
    ),
#BytesInteger(1),
  "data" / Bytes( this.header_len * 8 + 8 ),
  )


### Hop by Hop and Destination Extention Header :


DestinationAndHopByHopOptionType = Enum( Bytes( 1), 
  Pad1 = b'\x00',
  PadN = b'\x01',
#  Jumbo Payload = b'\xC2',
  JumboPayload = b'\xC2',
#  RPL Option = b'\x23',
  RPLOption = b'\x23',
#  RPL Option (DEPRECATED) = b'\x63',
#  Tunnel Encapsulation Limit = b'\x04',
  TunnelEncapsulationLimit = b'\x04',
#  Router Alert = b'\x05',
  RouterAlert = b'\x05',
#  Quick-Start = b'\x26',
  QuickStart = b'\x26',
  CALIPSO = b'\x07',
#  SMF_DPD = b'\x08',
  SMFDPD = b'\x08',
#  Home Address = b'\xC9',
  HomeAddress = b'\xC9',
#  Endpoint Identification (DEPRECATED)= b'\x8A',
#  ILNP Nonce = b'\x8B',
  ILNPNonce = b'\x8B',
#  Line-Identification Option = b'\x8C',
  LineIdentificationOption = b'\x8C',
  Deprecated = b'\x4D',
#  MPL Option = b'\x6D',
  MPLOption = b'\x6D',
  IP_DFF = b'\xEE',
#  Performance and Diagnostic Metrics (PDM) = b'\x0F',
  PDM = b'\x0F',
#  Minimum Path MTU Hop-by-Hop Option = b'\x30',
  MinimumPathMTUHopbyHopOption = b'\x30',
#  IOAM Destination Option and IOAM Hop-by-Hop Option = b'\x11',
  IOAMDestinationOptionAndIOAMHopByHopOptionA = b'\x11',
#  IOAM Destination Option and IOAM Hop-by-Hop Option = b'\x31',
  IOAMDestinationOptionAndIOAMHopByHopOptionB = b'\x31',
  AltMark = b'\x12',
#  RFC3692-style Experiment 1 = b'\x1E',
  RFC3692StyleExperimentA = b'\x1E',
  RFC3692StyleExperimentB = b'\x3E',
  RFC3692StyleExperimentC = b'\x5E',
  RFC3692StyleExperimentD = b'\x7E',
  RFC3692StyleExperimentE = b'\x9E',
  RFC3692StyleExperimentF = b'\xBE',
  RFC3692StyleExperimentG = b'\xDE',
  RFC3692StyleExperimentH = b'\xFE',
)

## Options are not yet defined ... 
HopByHopOrDestinationOption = Struct( 
  "type" / DestinationAndHopByHopOptionType, 
   IfThenElse( this.type == 'Pad', 
     Const( b'' ),  
     Struct( Prefixed( BytesInteger(1), GreedyBytes ) 
     )
  )  
)

HopByHoporDestinationHeader = Struct(
  "next_header" / pyesp.h6.NextHeaderType,
  "options" / Prefixed( BytesInteger(1), GreedyRange( HopByHopOrDestinationOption ) )
)



FragmentHeader = Struct(
  "next_header" / pyesp.h6.NextHeaderType,
  "reserved" / Const( b'\x00' ),
  "fragment" / BitStruct(
    "offset" / BitsInteger(13),
    "res" / BitsInteger(2),
    "M" / BitsInteger(1)
  ),
  "identification" / Bytes( 4),
)



AuthenticationHeader = Struct(
  "next_header" / pyesp.h6.NextHeaderType,
  "header_len" / ExprAdapter(Int8ub,
        encoder = lambda obj,ctx: obj / 8 - 8,
        decoder = lambda obj,ctx: obj * 8 + 8,
    ),
#  "header_len" / BytesInteger(1),
  "reserved" / BytesInteger(2),
  "spi" / Bytes(4),
  "sn" / Bytes(4),
  "icv" / Bytes(this.header_len * 4 - 12 )  

)

#ExtentionHeader = Struct(
#  "_header_type" / this._.header_type,
#  Switch( this._header_type, {
#     "HOPOPT" : HopByHoporDestinationHeader, 
#     "IPv6Route" : pyesp.h6_route.RoutingHeader,
#     "IPv6Frag" : FragmentHeader,
#     "ESP" : pyesp.h6_esp.EncryptedESP,
#     "AH" : AuthenticationHeader,
#     "IPv6Opts" : HopByHoporDestinationHeader,
#     "MobilityHeader" : GenericExtentionHeader, 
#     "HIP" : pyesp.h6_esp.EncryptedESP,
#     "Shim6" : GenericExtentionHeader 
#  } )
#)


class HeaderExt:

  def __init__( self,
    next_header='IPv6NoNxt',
    header_len=None,
    header_type=None,
    data:bytes=b'',
    packed=None
    ):
    """ Generic Header """

    self.struct = GenericExtentionHeader  
    if packed != None:
      self.unpack( )
    else: 
      self.next_header = next_header
      self.header_len = header_len
      self.header_type = header_type
      self.data = data
      
  def pack( self ) -> bytes :
    if isinstance( self.data, bytes ) is False:
      raise ValueError( f"Unexpected type for data ({type(data)}). Expecting bytes" )    
    return GenericExtentionHeader.build( 
      {   "next_header" : self.next_header,
          "data" : self.data } ) 

  def unpack( self, packed:bytes ) -> dict :
    ext = struct.parse( packed )
    for k, v in ext.items():
      self.__dict__[ k ] = v
#    self.next_header = ext[ 'next_header' ]
#    self.data = ext[ 'data' ]
#    self.header_len = ext[ 'header_len' ]
    return ext    

  def show( self ):    
    """Display the Generic Header Extention
    """
    packed = self.pack( ) 
    print( "## self.struct.__class__ ##" )
    print( self.struct.parse( packed ) )
    print( "binary:" )
    print( packed )
    print( "\n" )

class HOPOPT:

  def __init__( self,
    next_header='IPv6NoNxt',
#    header_len=None,
    options:list=[],
    packed=None
    ):
    self.struct = HopByHoporDestinationHeader 
    self.header_type = 'HOPOPT'
    if packed != None:
      self.unpack( )
    else: 
      self.next_header = next_header
      self.header_len = header_len
      self.options = options

  def pack( self ):
    """ return the binary format of the extention

    self.options are expected to be Python Objects.
    """
    return self.struct.build( 
      {   "next_header" : self.next_header,
          "options" : [ o.unpack() for o in self.options ] } ) 

class Frag:

  def __init__( self,
    next_header='IPv6NoNxt',
#    header_len=None,
    offset=0, res=0, M=0,
    identification:bytes=secrets.token_bytes( 4 ),
    packed=None ):

    self.struct = HopByHoporDestinationHeader 
    self.header_type = 'IPv6-Frag'
    if packed != None:
      self.unpack( )
    else: 
      self.next_header = next_header
      self.offset = offset
      self.res = res
      self.M = M

  def pack( self ):
    return self.struct.build( 
        { "next_header" : self.next_header,
          "fragment" : { "offset" : self.offset,
                         "res" : self.res,
                         "M" : self.M }, 
          "identification" : self.identification } )

class AH:

  def __init__( self,
    next_header='IPv6NoNxt',
#    header_len=None,
    spi:bytes=secrets.token_bytes( 4 ),
    sn:bytes=secrets.token_bytes( 4 ),
    icv:bytes=secrets.token_bytes( 4 ),
    packed=None
    ):
    self.struct = AuthenticationHeader, 
    self.header_type = 'AH'
    if packed != None:
      self.unpack( )
    else: 
      self.next_header = next_header
      self.spi = spi
      self.sn = sn
      self.icv = icv

  def pack( self ):
    return self.struct.build( 
        { "next_header" : self.next_header,
          "spi" :  self.spi,
          "sn" : self.sn,
          "icv" :  Bytes(this.header_len * 4 - 12) } ) 


