from construct.core import *
from construct.lib import *

from ipstack import *
from ipaddress import IPv4Address, IPv6Address
from Crypto.Random import get_random_bytes

from ehc_esp import EHC_ESP

ip_header_byte = BitStruct(
    "version" / BitsInteger(4),
    "remainder" / BitsInteger(4),
)


class Pkt:
    def __init__(self, **kwargs):
        self.pkt = self.build_pkt(**kwargs)

    def mac_src(self, **kwargs):
        try:
            return kwargs['mac_src']
        except KeyError:
            return '00-01-02-03-04-05'

    def mac_dst(self, **kwargs):
        try:
            return kwargs['mac_src']
        except KeyError:
            return '00-01-02-03-04-05'

    def mac_header(self, **kwargs):
         return {'destination': self.mac_dst(**kwargs), \
                 'source': self.mac_src(**kwargs), \
                 'type': kwargs['next_layer']}

    def ip6_dst(self, **kwargs):
        try:
            return Ipv6Address.parse(IPv6Address(kwargs['ip6_dst']).packed)
        except KeyError:
            return Ipv6Address.parse(IPv6Address('::1').packed)

    def ip6_src(self, **kwargs):
        try:
            return Ipv6Address.parse(IPv6Address(kwargs['ip6_src']).packed)
        except KeyError:
            return Ipv6Address.parse(IPv6Address('::1').packed)
        

    def ip6_header(self, **kwargs):
        return {'header':{'version':6, 'traffic_class':0,'flow_label':0},\
                'payload_length': kwargs['next_layer_len'], \
                'protocol': kwargs['next_layer'], \
                'hoplimit':8, \
                'source':self.ip6_src(), 'destination':self.ip6_dst()}

    def ip4_header(self, **kwargs):
         pass

    def port_src(self, **kwargs):
        try:
            return kwargs['port_src']
        except KeyError:
            return Int16ub.parse(get_random_bytes(2))

    def port_dst(self, **kwargs):
        try:
            return kwargs['port_dst']
        except KeyError:
            return Int16ub.parse(get_random_bytes(2))

    def udp_header(self, **kwargs):
        return {'source':self.port_src(**kwargs),\
                'destination': self.port_dst(**kwargs), \
                'payload_length':kwargs['next_layer_len'], 'checksum':0 }

    def tcp_header(self, **kwargs):
        pass
        
    def payload(self, **kwargs):
        try:
            return kwargs['payload']
        except KeyError:
            return b''

    
    def build_pkt(self, **kwargs):
        ## need to generate len and checksum
        ## need to list the different layers
        ## 
        try:
            self.layers = kwargs['layers']
        except KeyError:
            self.layers = ['eth', 'IPv6','UDP']

        payload = self.payload(**kwargs)
        kwargs['next_layer_len'] = len(payload)
        self.layers.append('application')
        for i in range(len(self.layers)):
            kwargs['next_layer'] = self.layers[-i]
            current_layer = self.layers[-(i+1)]
            if current_layer == 'UDP':
                payload = { 'header': self.udp_header(**kwargs), \
                            'next': payload }
                kwargs['next_layer_len'] = len(layer4_udp.build(payload))
            elif current_layer == 'TCP':
                pass
            elif current_layer =='IPv6':
                payload = {'header': self.ip6_header(**kwargs), \
                           'next': payload }
                kwargs['next_layer_len'] = len(layer3_ipv6.build(payload))
            elif current_layer == 'eth':
                payload = {'header': self.mac_header(**kwargs), \
                           'next': payload }
                kwargs['next_layer_len'] = len(layer2_ethernet.build(payload))
            i+=1
                
        return payload

    def to_bytes(self):
        if self.layers[0] == 'eth':
            return layer2_ethernet.build(self.pkt)
        elif self.layers[0] == 'IPv6':
            return layer3_ipv6.build(self.pkt)
        elif self.layers[0] == 'IPv4':
            return layer3_ipv4.build(self.pkt)
        elif self.layers[0] == 'UDP':
            return layer4_udp.build(self.pkt)
        raise Error

    def from_bytes(self, byte_pkt):
        if self.layers[0] == 'eth':
            self.pkt = layer2_ethernet.parse(byte_pkt)
        elif self.layers[0] == 'IPv6':
            self.pkt = layer3_ipv6.parse(byte_pkt)
        elif self.layers[0] == 'IPv4':
            self.pkt = layer3_ipv4.parse(byte_pkt)
        elif self.layers[0] == 'UDP':
            self.pkt = layer4_udp.parse(byte_pkt)
        else:
            raise Error

    def has_esp(self):
        try:
            if self.pkt['header']['protocol'] == 'ESP':
                return True
        except KeyError:
            return False


    def show(self, pkt=None, sa=None):
        if self.has_esp() == False:
            return self.from_bytes(self.to_bytes())
        else:
            s = ""
            if pkt==None:
                layer = self.pkt
            else:
                layer = pkt
            while True:
                print(layer)
                if isinstance(layer, bytes):
                    print(layer)
                    break
                elif 'encrypted_payload' in layer.keys():
                    esp = EHC_ESP(sa)
                    s += "%s"%esp.from_bytes(esp.to_bytes(layer))
                    break
                elif 'protocol' in layer['header'].keys():
                    s+= "%s"%ipv6_header.parse(ipv6_header.build(layer['header']))
                else:
                    try:
                        s+= "%s"%udp_header,parse(udp_header.buid(layer['header']))
                    except:
                        pass
                layer = layer['next']
            return s

    def ip_header_from_bytes(self, byte_pkt):
        version = ip_header_byte.parse(Int8ub.build(byte_pkt[0]))['version']
        if version == 6:
            outer_ip = ipv6_header.parse(byte_pkt[:40])
        elif version == 4:
            outer_ip = ipv4_header.parse(byte_pkt[:20])
        else:
            outer_ip = None
        return outer_ip
 

    def ts(self):
        try:
            remote_address = self.pkt['header']['destination']
        except KeyError:
            remote_address = 'OPAQUE'
        try:
            local_address = self.pkt['header']['source']
        except KeyError:
            local_address = 'OPAQUE'
        try:
            next_layer_proto = self.pkt['header']['protocol']
            next_layer_pkt = self.pkt['next']
##            while next_layer_proto in ['IP_OPTIONS']:
##                next_layer_proto_pkt = upper_pkt['next']
        except KeyError:
            next_layer_proto = 'OPAQUE'
       
        if next_layer_proto in ['TCP', 'UDP']:
            local_port = next_layer_pkt['header']['source']
            remote_port = next_layer_pkt['header']['destination']
        else:
            local_port = 'OPAQUE'
            remote_port = 'OPAQUE'
        return {'remote_address': remote_address,\
                'local_address': local_address,\
                'next_layer_proto': next_layer_proto,\
                'remote_port': remote_port,\
                'local_port': local_port}

