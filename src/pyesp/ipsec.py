#from pkt import Pkt
#from ipstack import ipv6_header, ipv4_header, Ipv6Address, IpAddress
from ipaddress import IPv4Address, IPv6Address
#from ehc_esp import EHC_SA, EHC_ESP
import pyesp
import pyesp.openschc_k
import pyesp.schc
from pyesp.h6_esp import ESP
from pyesp.sa import SA

class SP:
    def __init__(self):
        self.policy = 'PROTECT'
        self.tunnel_header = ('::1', '::1')
        self.path_mtu = None
        ## TS from spd
        self.ext_seq_num_flag = True ## we need this to specify the type
                                     ## (32 vs 64 bit of the seq_num)
        self.local_address = "ANY" ## "ANY" or range []
        self.remote_address = "ANY" ## "ANY" or range []
        self.next_layer_proto = "ANY"
        self.local_port = "ANY" ## "ANY" or range
        self.remote_port = "ANY" # or range
  
    def reverse(self):
        sp = SP()        
        sp.policy = self.policy
        sp.tunnel_header = (self.tunnel_header[1], self.tunnel_header[0])
        sp.local_address = self.remote_address
        sp.remote_address = self.local_address
        sp.local_port = self.remote_port
        sp.remote_port = self.local_port
        sp.path_mtu = self.path_mtu
        sp.ext_seq_num_flag = self.ext_seq_num_flag
        sp.next_layer_proto = self.next_layer_proto
        return sp

    def match_ip(self, ip_range, ip):
        if ip_range == 'ANY':
            return True
        try:
            ip = IPv6Address(Ipv6Address.build(ip))
        except:
            ip = IPv4Address(IpAddress.build(ip))

        try:
            ip_range = [IPv6Address(ip_range[0]), IPv6Address(ip_range[1])]
        except:
            ip_range = [IPv4Address(ip_range[0]), IPv4Address(ip_range[1])]
        if ip_range[0] <= ip <= ip_range[1]:
            return True
        return False

    def match_local_address(self, ip):
        return self.match_ip(self.local_address, ip)

    def match_remote_address(self, ip):
        return self.match_ip(self.remote_address, ip)


    def match_port(self, port_range, port):
        if port_range == 'ANY':
            return True
        if port_range[0] <= port <= port_range[1]:
            return True
        return False

    def match_local_port(self, port):
        return self.match_port(self.local_port, port)

    def match_remote_port(self, port):
        return self.match_port(self.remote_port, port)


    def match_next_layer_proto(self, next_layer_proto):
        if next_layer_proto == 'ANY':
            return True
        if self.next_layer_proto == next_layer_proto:
            return True
        return False

    def match(self, ts):
        if self.match_remote_address(ts['remote_address']) and\
           self.match_local_address(ts['local_address']) and\
           self.match_remote_port(ts['remote_port']) and\
           self.match_local_port(ts['local_port']):
            return True
        return False
  
    def create_sa(self):
        sa = EHC_SA()
        sa.mode = self.mode
        sa.tunnel_header = self.tunnel_header
        sa.path_mtu = None
        ## TS from selfd
        sa.ext_seq_num_flag = True ## we need this to selfecify the type
                                     ## (32 vs 64 bit of the seq_num)
        sa.local_address = self.local_address ## "ANY" or range []
        sa.remote_address = self.remote_address ## "ANY" or range []
        sa.next_layer_proto = self.next_layer_proto
        sa.local_port = self.local_port ## "ANY" or range
        sa.remote_port = self.remote_port # or range
        return sa   

class SPD:

    def __init__(self, sp_list):
        self.spd = sp_list
        self.spd.append(self.last_sp())

    def last_sp(self):
        sp = SP()
        sp.policy = 'DISCARD'
        sp.local_address = 'ANY'
        sp.remote_address = 'ANY'
        sp.next_layer_proto = 'ANY'
        sp.local_port = 'ANY'
        sp.remote_port = 'ANY'
        return sp

    def get_sp_from_ts(self, ts):
        for sp in self.spd:
            if sp.match(ts) == True:
                return sp




class SAD:

    def __init__(self):
        self.sad = []

    def get_sa_from_ts(self, ts):
        for sa in self.sad:
            if sa.match(ts) == True:
                return sa
        return None 

    def get_sa_from_spi(self, spi):
        self.sad[0].show()
        print("Show SA SPI")
        for spi_len in [4, 3, 2, 1, 0]:
            spi = spi[:spi_len]
            for sa in self.sad:
                if spi == sa.sec_param_index[:spi_len]:
                    if spi_len == 4:
                        return sa
                    if isinstance(sa, EHC_SA) == False:
                        continue
                    if sa.esp_spi_lsb == spi_len:
                        return sa
        return None

    def append(self, sa):
        self.sad.append(sa)

class IPsec:

    def __init__(self, sp_list=[], template=None):
        self.spd = SPD(sp_list)
        self.sad = SAD()
        self.template = None
   
    def syst_sa(self, sa):
        if self.template == 'ehc_iot':
            sa.ehc_strategy = "Diet-ESP"
            sa.esp_align = 8 
            sa.esp_spi_lsb = 2 
            sa.esp_sn_lsb = 2
        elif self.template == 'ehc_vpn':
            sa.ehc_strategy = "Diet-ESP"
            sa.esp_align = 8 
            sa.esp_spi_lsb = 2 
            sa.esp_sn_lsb = 2 
        else:
            sa.ehc_strategy = "NULL"
        return sa    

    def outbound_esp( self, ip6, sa):
###      ## Pre-ESP compression
###      ## Maybe this is cleaner to have it inside ESP
###      ## so it can be considered by the pack and unpack 
###      ## functions
      if sa.ehc_pre_esp  is not None:
###        ## This is only correct if compression only applies 
###        ## to UDP, but compression may also include the full
###        ## IPv6 packet in a tunnel mode.
###        ## The resulting Compression is ALWAYS a bytes
###        ## Maybe we define a specific object for SCHC.
        pre_esp_k = pyesp.openschc_k.UDPKompressor( sa.ehc_pre_esp )
        schc_udp = pyesp.schc.SCHC( data=pre_esp_k.schc( ip6.payload.pack() ) )
        ip6.nh = 146
        ip6.payload = schc_udp
        ip6.len = len( schc_udp.data ) ## to be checked if len is correct 
      if sa.mode == 'tunnel':
        x_esp = pyesp.h6_esp.ESP( sa=sa, data=ip6) 
###        ## SCHC compression for the encrypted ESP
###        ## We NEED to keep next_header as ESP.
        if sa.ehc_esp is not None:
          pass     
        tun_h6 = pyesp.h6.H6( src_ip=sa.tunnel_src_ip,
                dst_ip=sa.tunnel_dst_ip, next_header='ESP' )

        tun_ip6 = pyesp.ip6.IP6( header=tun_h6, 
                ext_header_list= [ x_esp ] )
        return tun_ip6
      elif sa.mode == 'transport':
        ## next_header value is carried by the last 
        ## extension header of the IPv6 header
        hx_len = len( ip6.ext_header_list )
        if hx_len == 0:
          esp_next_header = ip6.header.next_header  
          ip6.header.next_header = 'ESP'
        else:
          esp_next_header = ip6.ext_header_list[ -1 ].next_header  
          ip6.ext_header_list[ -1 ].next_header = 'ESP'
        x_esp = pyesp.h6_esp.ESP( sa=sa, data=ip6.payload,\
                next_header=esp_next_header )
        ip6.ext_header_list.append( x_esp )
        ip6.payload = b''
        return ip6
      else: 
        raise ValueError( "unknown IPsec mode: {sa.mode}" )

    def inbound_esp( self, ip6, sa):
      x_esp = ip6.ext_header_list[ -1 ]  
      x_esp.sa = sa
      x_esp.unpack( x_esp.pack( ) )
      if sa.mode == 'tunnel':
        return x_esp.data
      elif sa.mode == 'transport':
        ## removing ESP extension
        ip6.ext_header_list.pop( )
        ## updating the next_header
        hx_len = len( ip6.ext_header_list )
        if hx_len == 0:
          ip6.header.next_header = x_esp.next_header
        else:
          ip6.ext_header_list[ -1 ].next_header = x_esp.next_header
        if isinstance( x_esp.data, list ):
          ip6.ext_header_list.expand( x_esp.data[ : -1 ] )
          ip6.payload = x_esp.data[ -1 ]
        elif isinstance( x_esp.data, pyesp.udp.UDP ):  
          ip6.payload = x_esp.data
        elif isinstance( x_esp.data, bytes ):  
          ip6.unpack( ip6.pack() + x_esp.data )
        return ip6 

           
    def from_bytes(self, byte_pkt):
        ## checking ip header
        outer_pkt = Pkt()
        outer_ip = outer_pkt.ip_header_from_bytes(byte_pkt)
        if outer_ip == None:
            return None
        ## non ESP packet
        if outer_ip['protocol'] != 'ESP':
             if outer_ip['version'] == 6:
                 pkt = Pkt(layers=['IPv6'])
             else:
                 pkt = Pkt(layers=['IPv4'])
             pkt.from_bytes(byte_pkt)
             sp = self.spd_get_sp_from_ts(pkt.ts())
             if sp.policy == 'BYPASS':
                return pkt
             return None
        ## ESP packet
        sa = self.sad.get_sa_from_spi(byte_pkt[40:44])
        if isinstance(sa, SA):
            esp = ESP(sa)
        elif isinstance(sa, EHC_SA):
            esp = EHC_ESP(sa)
        encrypted_esp = esp.from_bytes(byte_pkt[40:])
        ct_esp = esp.unpack(encrypted_esp)
        if sa.mode == 'tunnel':
            pkt = Pkt()
            return pkt.from_bytes(ct_esp['data'])
        elif sa.mode == 'transport':
            pkt = Pkt(layers=['UDP'])
            return {'header': outer_ip, 'next':  pkt.pkt}


    def get_sa_sp_from_pkt(self, pkt):
        inner_pkt = self.dict_to_pkt(pkt)
        sa = self.sad.get_sa_from_ts(inner_pkt.ts())
        sp = self.spd.get_sp_from_ts(inner_pkt.ts())
        if sa == None and sp.policy == 'PROTECT':
            sa = sp.create_sa()
            sa = self.syst_sa(sa)
            self.sad.append(sa)
        return sa, sp

    def dict_to_pkt(self, pkt):
        try:
            ip_version = pkt['header']['header']['version']
            next_layer_proto = pkt['header']['protocol']
        except KeyError:
            ip_version = None
        if ip_version == 4:
            inner_pkt = Pkt(layers=['IPv4', 'UDP'])
        elif ip_version == 6:
            inner_pkt = Pkt(layers=['IPv6', 'UDP'])
        else:
            inner_pkt = Pkt(layers=['application'])
        inner_pkt.pkt = pkt
        return inner_pkt

    def outbound(self, pkt):

        sa, sp = self.get_sa_sp_from_pkt(pkt) 
        if sp.policy == 'BYPASS':
            return pkt
        elif sp.policy == 'DISCARD':
            return {}

        esp = EHC_ESP(sa)
        ip_version = pkt['header']['header']['version']
        if sa.mode == 'tunnel':
            if ip_version == 4:
                next_header = 'IPv4'
            else: #pkt['header']['version'] == 6:
                next_header = 'IPv6'
            payload = self.dict_to_pkt(pkt)
            esp_pkt = esp.pack(payload.to_bytes(), next_header=next_header)
            byte_esp_pkt = esp.to_bytes(esp_pkt)
            try:
                IPv6Address(sa.tunnel_header[0])
                outbound_pkt = Pkt(ip6_src=sa.tunnel_header[0], \
                                   ip6_dst=sa.tunnel_header[1], \
                                   payload=byte_esp_pkt, \
                                   layers=['IPv6', 'ESP'])
            except:
                outbound_pkt = Pkt(ip4_src=sa.tunnel_header[0], \
                                   ip4_dst=sa.tunnel_header[1], \
                                   payload=byte_esp_pkt, \
                                   layers=['IPv4', 'ESP'])
            outbound_pkt.pkt['next']=esp_pkt
            return outbound_pkt.pkt
        elif sa.mode == 'transport':
            next_header = pkt['header']['protocol']
            if next_header == 'UDP':
                payload = Pkt(layers=['UDP'])
            elif next_header == 'TCP':
                payload = Pkt(layers=['TCP'])
            payload.pkt = pkt['next']
            esp_pkt = esp.pack(payload.to_bytes(), next_header=next_header)
            byte_esp_pkt = esp.to_bytes(esp_pkt)
            pkt['header']['protocol'] = 'ESP'
            pkt['header']['payload_length'] = len(byte_esp_pkt)
            pkt['next'] = esp_pkt
            return pkt
            
            
    def to_bytes(self, pkt, ct_pkt):
##        if pkt['header']['protocol'] == 'ESP':
        sa, sp = self.get_sa_sp_from_pkt(ct_pkt)
        if sp.policy == 'BYPASS':
            outbound_pkt = Pkt()
            outbound_pkt.pkt = pkt
            return outbound_pkt.to_bytes()
        elif sp.policy == 'DISCARD':
            return b''

        esp = EHC_ESP(sa)
        ip_version = pkt['header']['header']['version']
        if ip_version == 6:
            if pkt['header']['protocol'] == 'ESP':
                payload = pkt['next'] 
                return ipv6_header.build(pkt['header']) + \
                       esp.to_bytes(payload) 
            else:
                outbound = Pkt(layers=['IPv6', 'UDP'])
                outbound.pkt = pkt
                return outbound.to_bytes()
        elif ip_version == 4:
            if outer_ip['header']['protocol'] == 'ESP':
                return ipv4_header.build(pkt['header']) + \
                       esp.to_bytes(pkt['next']) 
            else:
                outbound=Pkt(layers=['IPv4', 'UDP'])
                outbound.pkt = outer_ip
                return outbound.to_bytes()



##class IPsecStack:
##
##    def __init__(self, sp_list, template):
##        self.spd = SPD(sp_list)
##        self.sad = SAD()
##        self.template = None
##   
##    def syst_sa(self, sa):
##        if self.template == 'ehc_iot':
##            sa.ehc_strategy = "Diet-ESP"
##            sa.esp_align = 8 
##            sa.esp_spi_lsb = 2 
##            sa.esp_sn_lsb = 2
##        elif self.template == 'ehc_vpn':
##            sa.ehc_strategy = "Diet-ESP"
##            sa.esp_align = 8 
##            sa.esp_spi_lsb = 2 
##            sa.esp_sn_lsb = 2 
##        else:
##            sa.ehc_strategy = "NULL"
##        return sa    
##
##
##    def from_bytes(self, byte_pkt):
##        ## checking ip header
##        outer_pkt = Pkt()
##        outer_ip = outer_pkt.ip_header_from_bytes(byte_pkt)
##        if outer_ip == None:
##            return None
##        ## non ESP packet
##        if outer_ip['protocol'] != 'ESP':
##             if outer_ip['version'] == 6:
##                 pkt = Pkt(layers=['IPv6'])
##             else:
##                 pkt = Pkt(layers=['IPv4'])
##             pkt.from_bytes(byte_pkt)
##             sp = self.spd_get_sp_from_ts(pkt.ts())
##             if sp.policy == 'BYPASS':
##                return pkt
##             return None
##        ## ESP packet
##        sa = self.sad.get_sa_from_spi(byte_pkt[40:44])
##        if isinstance(sa, SA):
##            esp = ESP(sa)
##        elif isinstance(sa, EHC_SA):
##            esp = EHC_ESP(sa)
##        encrypted_esp = esp.from_bytes(byte_pkt[40:])
##        ct_esp = esp.unpack(encrypted_esp)
##        if sa.mode == 'tunnel':
##            pkt = Pkt()
##            return pkt.from_bytes(ct_esp['data'])
##        elif sa.mode == 'transport':
##            pkt = Pkt(layers=['UDP'])
##            return {'header': outer_ip, 'next':  pkt.pkt}
##
##
##    def get_sa_sp_from_pkt(self, pkt):
##        inner_pkt = self.dict_to_pkt(pkt)
##        sa = self.sad.get_sa_from_ts(inner_pkt.ts())
##        sp = self.spd.get_sp_from_ts(inner_pkt.ts())
##        if sa == None and sp.policy == 'PROTECT':
##            sa = sp.create_sa()
##            sa = self.syst_sa(sa)
##            self.sad.append(sa)
##        return sa, sp
##
##    def dict_to_pkt(self, pkt):
##        try:
##            ip_version = pkt['header']['header']['version']
##            next_layer_proto = pkt['header']['protocol']
##        except KeyError:
##            ip_version = None
##        if ip_version == 4:
##            inner_pkt = Pkt(layers=['IPv4', 'UDP'])
##        elif ip_version == 6:
##            inner_pkt = Pkt(layers=['IPv6', 'UDP'])
##        else:
##            inner_pkt = Pkt(layers=['application'])
##        inner_pkt.pkt = pkt
##        return inner_pkt
##
##    def outbound(self, pkt):
##
##        sa, sp = self.get_sa_sp_from_pkt(pkt) 
##        if sp.policy == 'BYPASS':
##            return pkt
##        elif sp.policy == 'DISCARD':
##            return {}
##
##        esp = EHC_ESP(sa)
##        ip_version = pkt['header']['header']['version']
##        if sa.mode == 'tunnel':
##            if ip_version == 4:
##                next_header = 'IPv4'
##            else: #pkt['header']['version'] == 6:
##                next_header = 'IPv6'
##            payload = self.dict_to_pkt(pkt)
##            esp_pkt = esp.pack(payload.to_bytes(), next_header=next_header)
##            byte_esp_pkt = esp.to_bytes(esp_pkt)
##            try:
##                IPv6Address(sa.tunnel_header[0])
##                outbound_pkt = Pkt(ip6_src=sa.tunnel_header[0], \
##                                   ip6_dst=sa.tunnel_header[1], \
##                                   payload=byte_esp_pkt, \
##                                   layers=['IPv6', 'ESP'])
##            except:
##                outbound_pkt = Pkt(ip4_src=sa.tunnel_header[0], \
##                                   ip4_dst=sa.tunnel_header[1], \
##                                   payload=byte_esp_pkt, \
##                                   layers=['IPv4', 'ESP'])
##            outbound_pkt.pkt['next']=esp_pkt
##            return outbound_pkt.pkt
##        elif sa.mode == 'transport':
##            next_header = pkt['header']['protocol']
##            if next_header == 'UDP':
##                payload = Pkt(layers=['UDP'])
##            elif next_header == 'TCP':
##                payload = Pkt(layers=['TCP'])
##            payload.pkt = pkt['next']
##            esp_pkt = esp.pack(payload.to_bytes(), next_header=next_header)
##            byte_esp_pkt = esp.to_bytes(esp_pkt)
##            pkt['header']['protocol'] = 'ESP'
##            pkt['header']['payload_length'] = len(byte_esp_pkt)
##            pkt['next'] = esp_pkt
##            return pkt
##            
##            
##    def to_bytes(self, pkt, ct_pkt):
####        if pkt['header']['protocol'] == 'ESP':
##        sa, sp = self.get_sa_sp_from_pkt(ct_pkt)
##        if sp.policy == 'BYPASS':
##            outbound_pkt = Pkt()
##            outbound_pkt.pkt = pkt
##            return outbound_pkt.to_bytes()
##        elif sp.policy == 'DISCARD':
##            return b''
##
##        esp = EHC_ESP(sa)
##        ip_version = pkt['header']['header']['version']
##        if ip_version == 6:
##            if pkt['header']['protocol'] == 'ESP':
##                payload = pkt['next'] 
##                return ipv6_header.build(pkt['header']) + \
##                       esp.to_bytes(payload) 
##            else:
##                outbound = Pkt(layers=['IPv6', 'UDP'])
##                outbound.pkt = pkt
##                return outbound.to_bytes()
##        elif ip_version == 4:
##            if outer_ip['header']['protocol'] == 'ESP':
##                return ipv4_header.build(pkt['header']) + \
##                       esp.to_bytes(pkt['next']) 
##            else:
##                outbound=Pkt(layers=['IPv4', 'UDP'])
##                outbound.pkt = outer_ip
##                return outbound.to_bytes()
##

