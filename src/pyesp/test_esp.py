from sa import *
from esp import *
from ehc_esp import *
from pkt import *
from ipsec import *
import copy

def print_struct(dict_payload, byte_payload, payload):
    print("    - dict_payload : %s"%dict_payload)
    print("    - byte_payload : %s"%byte_payload)
    print("    - payload : %s"%payload)


def test_iiv_nonce(seq_num_counter=255, ext_seq_num_flag=True):
    print("Test IIV_Nonce Structure")
    nonce = IIV_Nonce.build({'seq_num_counter':seq_num_counter},\
                             ext_seq_num_flag=ext_seq_num_flag)
    print("    - IIV_Nonce: %s (seq_num_counter:%s)"%(nonce, seq_num_counter))
    print(IIV_Nonce.parse(nonce, ext_seq_num_flag=ext_seq_num_flag))
    print("\n\n")

def test_ct_esp_payload(data=b'Bonjour'):
    print("Test ClearTextESPPayload Structure")
    pad_len = - (2 + len(data))%4
    pad = Pad.build(range(pad_len + 1)[1:])
    dict_payload = {'data':data, 'pad':pad, \
                'pad_len':pad_len, 'next_header':59} 
    byte_payload = ClearTextESPPayload.build(dict_payload,\
                       pad_len=pad_len, data_len=len(data))
    pad_len = byte_payload[-2]
    data_len = len(byte_payload) - 2 - pad_len
    payload = ClearTextESPPayload.parse(byte_payload, pad_len=pad_len, \
              data_len=data_len) 
    print_struct(dict_payload, byte_payload, payload)
    print("\n\n")

def test_encrypted_esp_payload(encrypted_payload=b'bonjour'):
    print("Test EncryptedESPPayload Structure")
    dict_payload = {'encrypted_payload': encrypted_payload, \
                    'icv': b'\x01\x02\x03\x04\x05\x06\x07\x08' }
    byte_payload = EncryptedESPPayload.build(dict_payload, icv_len=8,\
        encrypted_payload_len=len(encrypted_payload))
    
    payload = EncryptedESPPayload.parse(byte_payload, icv_len=8,\
         encrypted_payload_len=len(byte_payload) - 8)
    print_struct(dict_payload, byte_payload, payload)
    print("\n\n")

def test_pack_unpack(data=b'bonjour'):
    sa = SA()
    esp = ESP(sa)
    print("Test pack/unpack")
    print("    - data:%s"%data)
    print("    - pack:%s"%esp.pack(data))
    print("    - unpack:%s"%esp.unpack(esp.pack(data)))
    print("\n\n")
    
def test_to_from_bytes(data=b'bonjour'):
    sa = SA()
    esp = ESP(sa)
    print("Test to_bytes/from_bytes")
    print("    - data:%s"%data)
    esp_pkt = esp.pack(data)
    print("    - (pack) esp_pkt:%s"%esp_pkt)
    byte_esp_pkt = esp.to_bytes(esp_pkt)
    print("    - (to_bytes) byte_esp_pkt:%s"%byte_esp_pkt)
    esp_pkt = esp.from_bytes(byte_esp_pkt)
    print("    - (from_bytes) esp_pkt:%s"%esp_pkt)
    data = esp.unpack(esp_pkt)
    print("    - (unpack) data:%s"%data)
    print("\n\n")


def get_all_ehc_sa():
    sa_list = []
    for ehc_strategy in [ "NULL", "Diet-ESP"]:
        for esp_align in [1, 2, 3, 4]:
            for spi_lsb in range(5):
                for esp_sn_lsb in range(5):
                    for tcp_urgent in ["compress", "uncompress"]:
                        for tcp_options in ["compress", "uncompress"]:
                            for tcp_lsb in range(5):
                                 sa = EHC_SA()
                                 sa.ehc_strategy = ehc_strategy
                                 sa.esp_align = esp_align
                                 sa.spi_lsb = spi_lsb
                                 sa.esp_sn_lsb = esp_sn_lsb
                                 sa.tcp_urgent = tcp_urgent
                                 sa.tcp_options = tcp_options
                                 sa.tcp_lsb = tcp_lsb
                                 sa_list.append(sa)
    return sa_list


def test_ehc_pack_unpack(data=b'bonjour'):
    sa = EHC_SA()
    esp = EHC_ESP(sa)
    print("Test EHC pack/unpack")
    print("    - data:%s"%data)
    print("    - pack:%s"%esp.pack(data))
    print("    - unpack:%s"%esp.unpack(esp.pack(data)))
    print("\n\n")

def test_ehc_to_from_bytes(data=b'bonjour'):
    sa = EHC_SA()
    esp = EHC_ESP(sa)
    print("Test EHC to_bytes/from_bytes")
    print("    - data:%s"%data)
    esp_pkt = esp.pack(data)
    print("    - (pack) esp_pkt:%s"%esp_pkt)
    byte_esp_pkt = esp.to_bytes(esp_pkt)
    print("    - (to_bytes) byte_esp_pkt:%s"%byte_esp_pkt)
    esp_pkt = esp.from_bytes(byte_esp_pkt)
    print("    - (from_bytes) esp_pkt:%s"%esp_pkt)
    data = esp.unpack(esp_pkt)
    print("    - (unpack) data:%s"%data)
    print("\n\n")


def test_all_ehc(data=b'bonjour'):
    print("Testing all EHC configuration")
    for sa in get_all_ehc_sa():
        esp = EHC_ESP(sa)
        esp_pkt = esp.pack(data)
        byte_esp_pkt = esp.to_bytes(esp_pkt)
        esp_pkt = esp.from_bytes(byte_esp_pkt)
        rcv_data = esp.unpack(esp_pkt)
        if rcv_data['data'] != data:
            raise Error

##for ext_seq_num_flag in [True, False]:
##    seq_num_counter = 255
##    test_iiv_nonce(seq_num_counter, ext_seq_num_flag)
##
##for data in [b'bonjour']:
##    test_ct_esp_payload(data=data)
##
##test_encrypted_esp_payload()
##test_pack_unpack()
##test_to_from_bytes()
##test_ehc_pack_unpack(data=b'bonjour')
test_ehc_to_from_bytes(data=b'bonjour')
##test_all_ehc()

def test_pkt( layers ):
    print("Testing pkt with layers %s"%layers)
    pkt = Pkt(payload=b'bonjour', layers=layers)
    print("    - pkt (dict): %s"%pkt.pkt)
    byte_pkt = pkt.to_bytes()
    print("    - pkt (bytes):%s"%byte_pkt)
    print("    - pkt (dict): %s"%pkt.from_bytes(byte_pkt))
    print("\n\n")

##for layers in [ ['eth', 'IPv6', 'UDP'], ['IPv6', 'UDP'], \
##                ['UDP'], ['IPv6', 'ESP'], ['IPv6'],\
##                ['IPv4']]: #, ['application']]: 
#, 'UDP'#    test_pkt(layers)


def sp_ts_vpn():
    sp = SP()
    sp.local_address = [IPv6Address('::1'), IPv6Address('::1')]
    sp.remote_address = 'ANY'
    sp.next_layer_proto = 'ANY'
    sp.local_port = 'ANY'
    sp.remote_port = 'ANY'
    return sp

def sp_ts_mono():
    sp = SP()
    sp.local_address = [IPv6Address('::1'), IPv6Address('::1')]
    sp.remote_address = [IPv6Address('::1'), IPv6Address('::1')]
    sp.next_layer_proto = 'UDP'
    sp.local_port = [26981, 26981]
    sp.remote_port = [80, 80]
    return sp


def ipsec_stack_conf(ts_type, mode, ehc):
    if ts_type == 'vpn':
        sp = sp_ts_vpn()
    else:
        sp = sp_ts_mono()
    sp.mode = mode
        
    if ehc == False:
        template = None
    elif ts_type == 'vpn':
        template = 'ehc_vpn'
    else:
        template = 'ehc_iot'
    return sp, template

def test_ipstack(): 
    for ts_type in ['vpn', 'mono']:
        for mode in ['transport', 'tunnel']:
            for ehc in [ True, False]:
                print("Testing ts: %s - mode: %s - ehc: %s"%(ts_type, mode, ehc))
                sp, template = ipsec_stack_conf(ts_type, mode, ehc)
                ipsec_i = IPsecStack([sp, sp.reverse()], template)
                ipsec_r = IPsecStack([sp, sp.reverse()], template)
                pkt = Pkt(payload=b'bonjour', ip6_src='::1', ip6_dst='::1',\
                          port_src=26981, port_dst=80, layers=['IPv6', 'UDP'])
                init_pkt = copy.deepcopy(pkt.pkt)
                print("    - pkt (dict): %s"%pkt.show())
                byte_pkt = pkt.to_bytes()
                print("    - unprotected pkt (bytes):%s"%byte_pkt)
                ipsec_pkt = ipsec_i.outbound(pkt.pkt)
                pkt.pkt = ipsec_pkt 
                print("    - ipsec pkt -> (dict): %s"%pkt.show(sa=ipsec_i.sad.sad[0]))
                byte_ipsec_pkt = ipsec_i.to_bytes(ipsec_pkt, init_pkt)
                print("    - ipsec pkt -> (bytes): %s"%byte_ipsec_pkt)
                ipsec_r.sad = ipsec_i.sad
                ipsec_pkt = ipsec_r.from_bytes(byte_ipsec_pkt)
                print("    - ipsec pkt <- (bytes): %s"%ipsec_pkt)
                print("\n\n")

