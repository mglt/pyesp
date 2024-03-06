from construct import *
from construct.lib import *

import secrets
import pyesp.h6

## Routing Extension Header

RoutingType = Enum( BytesInteger(1),
#  Source Route                = 0
  SourceRoute                = 0,
  Nimrod                      = 1,
#  Type 2 Routing Header       = 2
  TypeTwoRoutingHeader       = 2,
#  RPL Source Route Header     = 3
  RPLSourceRouteHeader     = 3,
  SRH = 4,
#  CRH-16                      = 5
  CRHSixTeen                      = 5,
#  CRH-32                      = 6
  CRHThirstyTwo                    = 6,
#  RFC3692-style Experiment 1  = 253
  RFC3692StyleExperimentA  = 253,
  RFC3692StyleExperimentB  = 254,
  Reserved = 255
)

## segment routing data RFC8754

RouteOptionType = Enum( Bytes( 1),
  Pad1 = 0,
  PadN = 4,
  HMAC = 5,
)

#DType = Enum( BitsInteger(2), 
#  unset = 0,
#  set = 1
#)

Hmac = Struct( 
 'D' / BitStruct( Flag ),
 'RESERVED' / BitStruct(  BitsInteger(15) ),
 'key_id' / Bytes( 4 ),
 'hmac' / Bytes(32) 
)

RouteOption = Struct( 
  'type' / RoutingType, 
   IfThenElse( this.type == 'Pad',
     Const( b'' ),
     Struct( 
       Prefixed( BytesInteger(1), 
         Switch( this.type, { 
           'PadN' : GreedyBytes,  
           'HMAC' : Hmac } )
       )
     )
   )
) 

SRData = Struct(
  'last_entry' / BytesInteger(1),
  'flags' / Const( b'\x00\x00' ),
  'tag' / BytesInteger(2),
  'segment_list' / Array( this.last_entry, pyesp.h6.Ipv6Address ),
  'options' / GreedyRange( RouteOption )
)



## Routing Header
RoutingHeader = Struct(
  "next_header" / pyesp.h6.NextHeaderType,
  "header_len" / BytesInteger(1),
  "routing_type" / BytesInteger(1),
  "segment_left" / BytesInteger(1),
  'data' / Switch( this.routing_type, {
      'SRH' : SRData,
  })
)

class HMACOption:

  def __init__( self, 
    D=True, 
    key_id=secrets.randbits( 4 * 8 ), 
    hmac=None,
    packed=None):

    if packed is not None:
      self.unpacked( packed )
    else: 
      self.type = 'HMAC'  
      self.D = D
      self.key_id = key_id
  
  def compute_hmac( self, segment_list ):
    return secrets.randbytes( 32 )

  def pack( self ):
    return RouteOption.build(\
      { 'type' : self.type, 
        'D' : self.D,
        'key_id' : self.key_id, 
        'hmac' : self.compute_hmac( )} )
    
  def unpack( self, hmac_opt ):
    opt = RouteOption.parse( hmac_opt )
    self.__init__( **opt ) 
#    self.D = opt[ 'D' ]
#    self.key_id = opt[ 'key_id' ]
#    self.hmac = opt[ 'hmac' ]
    return opt


class SRH:  
 
  def __init__( self, 
    next_header='IPv6-NoNxt',
    tag:bytes=secrets.randbits( 2 ),
    segment_left=5, 
    segment_list:list=[], 
    options:list=[]):

    self.next_header = next_header  
    self.header_type = 'IPv6-Route'
    self.routing_type = 'SRH'

  def pack( self ):
    pass

  def unpack( self ):
    pass  
  
     


