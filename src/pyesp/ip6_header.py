## intersting links:
## https://github.com/construct/construct/blob/master/deprecated_gallery/ipstack.py
## https://github.com/ZiglioUK/construct
import secrets

from construct import *
from construct.lib import *

### IANA Registries
## https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
ProtocolType = Enum( BytesInteger(1), 
  HOPOPT = 0,
  ICMP = 1,
  IGMP = 2,
  GGP = 3,
  IPv4 = 4,
  ST = 5,
  TCP = 6,
  CBT = 7,
  EGP = 8,
  IGP = 9,
  BBN-RCC-MON = 10,
  NVP-II = 11,
  PUP = 12,
  ARGUS (deprecated) = 13,
  EMCON = 14,
  XNET = 15,
  CHAOS = 16,
  UDP = 17,
  MUX = 18,
  DCN-MEAS = 19,
  HMP = 20,
  PRM = 21,
  XNS-IDP = 22,
  TRUNK-1 = 23,
  TRUNK-2 = 24,
  LEAF-1 = 25,
  LEAF-2 = 26,
  RDP = 27,
  IRTP = 28,
  ISO-TP4 = 29,
  NETBLT = 30,
  MFE-NSP = 31,
  MERIT-INP = 32,
  DCCP = 33,
  3PC = 34,
  IDPR = 35,
  XTP = 36,
  DDP = 37,
  IDPR-CMTP = 38,
  TP++ = 39,
  IL = 40,
  IPv6 = 41,
  SDRP = 42,
  IPv6-Route = 43,
  IPv6-Frag = 44,
  IDRP = 45,
  RSVP = 46,
  GRE = 47,
  DSR = 48,
  BNA = 49,
  ESP = 50,
  AH = 51,
  I-NLSP = 52,
  SWIPE (deprecated) = 53,
  NARP = 54,
  Min-IPv4 = 55,
  TLSP = 56,
  SKIP = 57,
  IPv6-ICMP = 58,
  IPv6-NoNxt = 59,
  IPv6-Opts = 60,
  HOSTSRV = 61,
  CFTP = 62,
  LOCNET = 63,
  SAT-EXPAK = 64,
  KRYPTOLAN = 65,
  RVD = 66,
  IPPC = 67,
  DISFS = 68,
  SAT-MON = 69,
  VISA = 70,
  IPCV = 71,
  CPNX = 72,
  CPHB = 73,
  WSN = 74,
  PVP = 75,
  BR-SAT-MON = 76,
  SUN-ND = 77,
  WB-MON = 78,
  WB-EXPAK = 79,
  ISO-IP = 80,
  VMTP = 81,
  SECURE-VMTP = 82,
  VINES = 83,
  IPTM = 84,
  NSFNET-IGP = 85,
  DGP = 86,
  TCF = 87,
  EIGRP = 88,
  OSPFIGP = 89,
  Sprite-RPC = 90,
  LARP = 91,
  MTP = 92,
  AX.25 = 93,
  IPIP = 94,
  MICP = 95,
  SCC-SP = 96,
  ETHERIP = 97,
  ENCAP = 98,
  PRIVENC = 99,
  GMTP = 100,
  IFMP = 101,
  PNNI = 102,
  PIM = 103,
  ARIS = 104,
  SCPS = 105,
  QNX = 106,
  A/N = 107,
  IPComp = 108,
  SNP = 109,
  Compaq-Peer = 110,
  IPX-in-IP = 111,
  VRRP = 112,
  PGM = 113,
  ZHOP = 114,
  L2TP = 115,
  DDX = 116,
  IATP = 117,
  STP = 118,
  SRP = 119,
  UTI = 120,
  SMP = 121,
  SM (deprecated) = 122,
  PTP = 123,
  ISIS over IPv4 = 124,
  FIRE = 125,
  CRTP = 126,
  CRUDP = 127,
  SSCOPMCE = 128,
  IPLT = 129,
  SPS = 130,
  PIPE = 131,
  SCTP = 132,
  FC = 133,
  RSVP-E2E-IGNORE = 134,
  Mobility Header = 135,
  UDPLite = 136,
  MPLS-in-IP = 137,
  manet = 138,
  HIP = 139,
  Shim6 = 140,
  WESP = 141,
  ROHC = 142,
  Ethernet = 143,
  AGGFRAG = 144,
  NSH = 145,
  EXP1 = 253,
  EXP2 = 254,
  Reserved = 255,

)

ExtHeaderType = Enum( BytesInteger(1),
  HOPOPT = 0,
  IPv6-Route = 43,
  IPv6-Frag = 44,
  ESP = 50,
  AH = 51,
  IPv6-Opts = 60,
  Mobility Header = 135,
  HIP = 139,
  Shim6 = 140,
  EXP1 = 253,
  EXP2 = 254,
  )

DestinationAndHopByHopOptionType = Enum( Bytes( 1), 
  Pad1 = b'\x00',
  PadN = b'\x01',
  Jumbo Payload = b'\xC2',
  RPL Option = b'\x23',
#  RPL Option (DEPRECATED) = b'\x63',
  Tunnel Encapsulation Limit = b'\x04',
  Router Alert = b'\x05',
  Quick-Start = b'\x26',
  CALIPSO = b'\x07',
  SMF_DPD = b'\x08',
  Home Address = b'\xC9',
#  Endpoint Identification (DEPRECATED)= b'\x8A',
  ILNP Nonce = b'\x8B',
  Line-Identification Option = b'\x8C',
  Deprecated = b'\x4D',
  MPL Option = b'\x6D',
  IP_DFF = b'\xEE',
  Performance and Diagnostic Metrics (PDM) = b'\x0F',
  Minimum Path MTU Hop-by-Hop Option = b'\x30',
  IOAM Destination Option and IOAM Hop-by-Hop Option = b'\x11',
  IOAM Destination Option and IOAM Hop-by-Hop Option = b'\x31',
  AltMark = b'\x12',
  RFC3692-style Experiment 1 = b'\x1E',
  RFC3692-style Experiment 2 = b'\x3E',
  RFC3692-style Experiment 3 = b'\x5E',
  RFC3692-style Experiment 4 = b'\x7E',
  RFC3692-style Experiment 5 = b'\x9E',
  RFC3692-style Experiment 6 = b'\xBE',
  RFC3692-style Experiment 7 = b'\xDE',
  RFC3692-style Experiment 8 = b'\xFE',
)


RoutingType = Enum( BytesInteger(1), 
  Source Route                = 0	
  Nimrod                      = 1	
  Type 2 Routing Header       = 2	
  RPL Source Route Header     = 3	
  Segment Routing Header (SRH) = 4
  CRH-16                      = 5	
  CRH-32                      = 6	
  RFC3692-style Experiment 1  = 253	
  RFC3692-style Experiment 2  = 254	
  Reserved = 255
)

##NextHeader = Enum(BytesInteger(1),
##    HOP_BY_HOP_OPTION_HEADER = 0,   # extention Hop-by-Hop Option
##    DESTINATION_OPTION_WITH_ROUTING = 60,
##    ROUTING_HEADER = 43, 
##    FRAGMENT_HEADER = 44, 
##    DESTINATION_OPTION = 60, 
##    MOBILITY_HEADER = 59,
##    IPv4 = 6,
##    TCP = 6,
##    UDP = 17,
##    IPv6 = 41,
##    ESP = 50,
##    AH = 51,
##    ICMPv6 =58, 
##    NO_NEXT_HEADER = 59,
##    SCTP = 132,
##    SCHC = 145
##)


### IPv6 Extention Header

GenericExtentionHeader = Struct(
  "next_header" / NextHeader OR Extendtion,
  "header_len" / BytesInteger(1),
  "data" / Bytes( this.header_len * 8 + 1),
  )


HopByHopOrDestinationOption = Struct( 
  "type" / DestinationAndHopByHopOptionType,       
  Prefixed( BytesInteger(1), GreedyBytes )
)

HopByHoporDestinationHeader = Struct(
  "next_header" / NextHeader OR Extendtion,
  "options" / Prefixed( BytesInteger(1), GreedyRange( HopByHopOrDestinationOption ) )
)

FragmentHeader = Struc(
  "next_header" / NextHeader OR Extendtion,
  "reserved" / Const( b'\x00' ),
  "fragment" / BitStruct(
    "offset" / BitsInteger(13),
    "res" / BitsInteger(2),
    "M" / BitsInteger(1)
  )
  "identification" / Bytes( 4),
)

RoutingHeader = Struct(
  "next_header" / NextHeader OR Extendtion,
  "header_len" / BytesInteger(1),
  "routing_type" / BytesInteger(1),
  "segment_left" / BytesInteger(1)
)

AuthenticationHeader = Struct(
  "next_header" / NextHeader OR Extendtion,
  "header_len" / BytesInteger(1),
  "reserved" / BytesInteger(2),
  "spi" / Bytes(4),
  "sn" / Bytes(4),
  "icv" / Bytes(this.header_len * 4 - 12 )  

)

ExtentionHeader = Struct(
  "_header_extention" / this._.header_extention,
  Switch( this._header_extention, {
     "HOPOPT" : HopByHoporDestinationHeader, 
     "IPv6-Route" : RoutingHeader,
     "IPv6-Frag" : FragmentHeader,
     "ESP" : EncryptedESP,
     "AH" : AuthenticationHeader,
     "IPv6-Opts" : HopByHoporDestinationHeader,
     "Mobility Header" : GenericExtentionHeader, 
     "HIP" : EncryptedESP,
     "Shim6" : GenericExtentionHeader 
  } )
)

########## end of IPv6 Extentions

DSCP = Enum( BitsInteger(6),
  CS0 = 0,
  CS1 = 8,
  CS2 = 16,
  CS3 = 24,
  CS4 = 32,
  CS5 = 40,
  CS6 = 48,
  CS7 = 56,
  AF11 = 10,
  AF12 = 12,
  AF13 = 14,
  AF21 = 18,
  AF22 = 20,
  AF23 = 22,
  AF31 = 26,
  AF32 = 28,
  AF33 = 30,
  AF41 = 34,
  AF42 = 36,
  AF43 = 38,
  EF = 46,
  VOICE-ADMIT = 44,
  LE = 1,
)


ECN = Enum( BitsInteger(2),
  Not-ECT = 0,
  ECT1 = 1,
  ECT0 = 2, 
  EC = 3
)

TrafficClass = Structure( 
  "dscp" / DSCP,
  "ecn" / ECN
)

Ipv6Address = ExprAdapter(Byte[16],
    decoder = lambda obj,ctx: ":".join("%02x" % b for b in obj),
    encoder = lambda obj,ctx: [int(part, 16) for part in obj.split(":")],
)


IPv6Header = Struct(
    "header" / BitStruct(
        "version" / OneOf(BitsInteger(4), [6]),
#        "traffic_class" / BitsInteger(8),
        "traffic_class" / TrafficFlow,
        "flow_label" / BitsInteger(20),
    ),
    "payload_length" / Int16ub,
    "next_header" / ProtocolEnum,
    "hop_limit" / Int8ub,
    "source_address" / Ipv6Address,
    "destination_address" / Ipv6Address,
)




class IP6Header:
  def __init__( self, version:int=6,
    dscp="AF11", 
    ecn="Not-ECT",
    flow_label=None:bytes, 
    payload_length=None, 
    next_header=None, 
    hop_limit:int=64, 
    source_address, 
    destination_addresse, 
    ext_headers:list=[], 
    payload=None):
    if version != 6:
      raise ValueError( f"unvalid version {version}. Expecting 6" )
    self.version = 6
    self.dscp=dscp
    self.ecn=ecn
    if flow_label is None:
      self.flow_label = secrets.randbits( 20 )
    else: 
      self.flow_label = flow_label
    self.payload_length=payload_length
    if next_header is None 

  def build_next_header( self ):
    if isinstance( self.ext_headers, list) :
      if len( self.ext_headers ) = 0:
        self.ext_headers
    if self.ext_headers not in  [ None, [] ]:
    if self.payload not in [ None  and 
      self.next_header = 'IPv6-NoNxt'
    elif self.payload is None

class IP6:
 
  def __init__( self ):
    self.header = None
    self.extention_headers = []
    
  def build( self, ):
    pass

  def parse( self, bytes_ip6:bytes, sa=None, debug=False ):
    if isinstance( bytes_ip6, bytes) is False:
      raise ValueError( f"expecting bytes, recievd {type(ip6)}" )
    if len( bytes_ip6 ) < 40 :
      raise ValueError( f"Not enough bytes ({len( ip6 )}. "\
                        f"Expectiong at least 40" )
    byte_pointer = 0 
    self.header = ipv6_header.parse( ip6[ byte_pointer:40 ] )
    byte_pointer = 40
    next_header = self.is_ext_header( self.header[ 'next_header' ] )
    while next_header is not None :
      if next_header == "Encapsulating Security Payload" :
        ext_header_bytes = bytes_ip6[ byte_pointer: ] 
        if sa is None:  
          icv_len = 0  ## in that case the encrypted includes the icv
        encrypted_payload_len = len( bytes_ip6 ) - byte_pointer \
                - 8 - icv_len 
        ext_header = ExtentionHeade.parse(\
                       ext_header_bytes,\
                       _next_header=next_header,\
                       encrypted_payload_len=encrypted_payload_len,\
                       icv_len=icv_len )
        self.extention_headers.append( ext_header )
        next_header = None 
        byte_pointer = len( bytes_ip6 )
      else :
        if next_header == "Authentication Header" :  
          length = 4 * ( bytes_ip6[ byte_pointer + 1 ] + 2 )
        else:
          length = 8 * ( bytes_ip6[ byte_pointer + 1 ] + 1 )
        ext_header_bytes = bytes_ip6[ byte_pointer: byte_pointer + length ]
        ext_header = ExtentionHeade.parse( \
                       ext_header_bytes,
                       _next_header=next_header )

        self.extention_headers.append( ext_header )
        next_header = bytes_ip6[ byte_pointer ]
        byte_pointer += length
          
  def build(          

  def is_ext_header( self, next_header ):
    try:
      return ExtHeaderType.parse( next_header )
    except MappingError:
      return None

    

