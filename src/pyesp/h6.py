## intersting links:
## https://github.com/construct/construct/blob/master/deprecated_gallery/ipstack.py
## https://github.com/ZiglioUK/construct
import secrets
import ipaddress
import binascii

from construct import *
from construct.lib import *

### IANA Registries
## https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
NextHeaderType = Enum( BytesInteger(1), 
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
#  BBN-RCC-MON = 10,
  BBNRCCMON = 10,
#  NVP-II = 11,
  NVPII = 11,
  PUP = 12,
  ARGUS = 13,
  EMCON = 14,
  XNET = 15,
  CHAOS = 16,
  UDP = 17,
  MUX = 18,
#  DCN-MEAS = 19,
  DCNMEAS = 19,
  HMP = 20,
  PRM = 21,
#  XNS-IDP = 22,
  XNSIDP = 22,
#  TRUNK-1 = 23,
  TRUNK1 = 23,
#  TRUNK-2 = 24,
  TRUNK2 = 24,
#  LEAF-1 = 25,
  LEAF1 = 25,
#  LEAF-2 = 26,
  LEAF2 = 26,
  RDP = 27,
  IRTP = 28,
#  ISO-TP4 = 29,
  ISOTP4 = 29,
  NETBLT = 30,
#  MFE-NSP = 31,
  MFENSP = 31,
#  MERIT-INP = 32,
  MERITINP = 32,
  DCCP = 33,
#  3PC = 34,
  ThreePC = 34,
  IDPR = 35,
  XTP = 36,
  DDP = 37,
#  IDPR-CMTP = 38,
  IDPRCMTP = 38,
#  TP++ = 39,
  TPplusplus = 39,
  IL = 40,
  IPv6 = 41,
  SDRP = 42,
#  IPv6-Route = 43,
  IPv6Route = 43,
#  IPv6-Frag = 44,
  IPv6Frag = 44,
  IDRP = 45,
  RSVP = 46,
  GRE = 47,
  DSR = 48,
  BNA = 49,
  ESP = 50,
  AH = 51,
#  I-NLSP = 52,
  INLSP = 52,
  SWIPE = 53,
  NARP = 54,
#  Min-IPv4 = 55,
  MinIPv4 = 55,
  TLSP = 56,
  SKIP = 57,
#  IPv6-ICMP = 58,
  IPv6ICMP = 58,
#  IPv6-NoNxt = 59,
  IPv6NoNxt = 59,
#  IPv6-Opts = 60,
  IPv6Opts = 60,
  HOSTSRV = 61,
  CFTP = 62,
  LOCNET = 63,
#  SAT-EXPAK = 64,
  SATEXPAK = 64,
  KRYPTOLAN = 65,
  RVD = 66,
  IPPC = 67,
  DISFS = 68,
#  SAT-MON = 69,
  SATMON = 69,
  VISA = 70,
  IPCV = 71,
  CPNX = 72,
  CPHB = 73,
  WSN = 74,
  PVP = 75,
#  BR-SAT-MON = 76,
  BRSATMON = 76,
#  SUN-ND = 77,
  SUNND = 77,
#  WB-MON = 78,
  WBMON = 78,
#  WB-EXPAK = 79,
  WBEXPAK = 79,
#  ISO-IP = 80,
  ISOIP = 80,
  VMTP = 81,
#  SECURE-VMTP = 82,
  SECUREVMTP = 82,
  VINES = 83,
  IPTM = 84,
#  NSFNET-IGP = 85,
  NSFNETIGP = 85,
  DGP = 86,
  TCF = 87,
  EIGRP = 88,
  OSPFIGP = 89,
#  Sprite-RPC = 90,
  SpriteRPC = 90,
  LARP = 91,
  MTP = 92,
#  AX.25 = 93,
  AXTwentyFive = 93,
  IPIP = 94,
  MICP = 95,
#  SCC-SP = 96,
  SCCSP = 96,
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
#  A/N = 107,
  AN = 107,
  IPComp = 108,
  SNP = 109,
#  Compaq-Peer = 110,
  CompaqPeer = 110,
#  IPX-in-IP = 111,
  IPXinIP = 111,
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
  SM = 122,
  PTP = 123,
#  ISIS over IPv4 = 124,
  ISISoverIPv4 = 124,
  FIRE = 125,
  CRTP = 126,
  CRUDP = 127,
  SSCOPMCE = 128,
  IPLT = 129,
  SPS = 130,
  PIPE = 131,
  SCTP = 132,
  FC = 133,
#  RSVP-E2E-IGNORE = 134,
  RSVPE2EIGNORE = 134,
#  Mobility Header = 135,
  MobilityHeader = 135,
  UDPLite = 136,
#  MPLS-in-IP = 137,
  MPLSinIP = 137,
  manet = 138,
  HIP = 139,
  Shim6 = 140,
  WESP = 141,
  ROHC = 142,
  Ethernet = 143,
  AGGFRAG = 144,
  NSH = 145,
  SCHC = 146,
  EXP1 = 253,
  EXP2 = 254,
  Reserved = 255,

)

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
#  VOICE-ADMIT = 44,
  VOICEADMIT = 44,
  LE = 1,
)


ECN = Enum( BitsInteger(2),
#  Not-ECT = 0,
  NotECT = 0,
  ECT1 = 1,
  ECT0 = 2, 
  EC = 3
)

TrafficClass = Struct( 
  "dscp" / DSCP,
  "ecn" / ECN
)


Ipv6Address = ExprAdapter(Bytes(16),
    decoder = lambda obj,ctx: ipaddress.IPv6Address( obj ).compressed,
    encoder = lambda obj,ctx: ipaddress.IPv6Address( obj ).packed,
)


IPv6Header = Struct(
    "_name" / Computed( 'IPv6Header' ),    
    "header" / BitStruct(
        "version" / BitsInteger(4, 6),
        "traffic_class" / TrafficClass,
        "flow_label" / BitsInteger(20),
    ),
    "payload_length" / Int16ub,
    "next_header" / NextHeaderType, 
    "hop_limit" / Int8ub,
    "src_ip" / Ipv6Address,
    "dst_ip" / Ipv6Address,
)




class H6:
  def __init__( self,
    dscp="LE", 
    ecn="NotECT",
    flow_label:bytes =secrets.randbits( 20 ), 
    payload_length=0, 
    next_header='IPv6NoNxt', 
    hop_limit:int =64, 
    src_ip=ipaddress.IPv6Address( '::a' ), 
    dst_ip=ipaddress.IPv6Address( '::b' ),
    packed=None):

    self.struct = IPv6Header
    self.version = 6
    self.header_type = 'IPv6'
    if packed is not None:
      self.unpack( packed )
    else:
      self.dscp=dscp
      self.ecn=ecn
      self.traffic_class = self.compute_traffic_class()
      self.flow_label = flow_label
      self.payload_length = payload_length
      self.next_header = next_header
      self.hop_limit = hop_limit
      self.src_ip = ipaddress.IPv6Address( src_ip )
      self.dst_ip = ipaddress.IPv6Address( dst_ip )


  def compute_traffic_class(self, dscp=None, ecn=None ):
    if dscp is None:
      dscp = self.dscp
    if ecn is None:
      ecn = self.ecn
    return TrafficClass.build( { 'dscp' :  dscp, 'ecn' : ecn } )

  def pack( self, ):
    return IPv6Header.build( \
      { 'header' : \
        { 'version' : self.version, 
          'traffic_class' : \
            { 'dscp' : self.dscp, 
              'ecn' : self.ecn },
          'flow_label' : self.flow_label }, 
        'payload_length' : self.payload_length,
        'next_header' :  self.next_header, 
        'hop_limit' : self.hop_limit, 
        'src_ip' : self.src_ip, 
        'dst_ip' : self.dst_ip } )

  def unpack( self, packed:bytes ):
    hdr = IPv6Header.parse( packed )
    self.dscp = hdr[ 'header' ][ 'traffic_class' ][ 'dscp' ] 
    self.ecn = hdr[ 'header' ][ 'traffic_class' ][ 'ecn' ] 
    self.flow_label =  hdr[ 'header' ][ 'flow_label' ]
    self.payload_length = hdr[ 'payload_length' ]
    self.next_header = hdr[ 'next_header' ]
    self.hop_limit = hdr[ 'hop_limit' ]
    self.src_ip = hdr[ 'src_ip' ]
    self.dst_ip = hdr[ 'dst_ip' ]

  def show( self ):    
    """Display the Generic Header Extention
    """
    packed = self.pack( )
    unpacked = self.struct.parse( packed )
    print( f"## {unpacked._name} ##" )
    print( unpacked ) 
    print( "binary:" )
    print( binascii.hexlify( packed, sep=' ' ) )
 
