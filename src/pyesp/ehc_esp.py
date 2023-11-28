from construct.core import *
from construct.lib import *
from esp import ESP, EncryptedESPPayload, NextHeader
from sa import SA

class EHC_SA(SA):
    
    def __init__(self):
        super().__init__()
        self.ehc_strategy = "Diet-ESP"
        self.esp_align = 1 # 1, 2, 3, 4
        self.esp_spi_lsb = 0 # 0, 1, 2, 3, 4
        self.esp_sn_lsb = 0 # 0, 1, 2, 3, 4
        self.tcp_urgent = "uncompress"
        self.tcp_options = "uncompress"
        self.tcp_sn_lsb = 4
        self.udp_lite_coverage = "udp" 
        self.check_conf()

    def sec_param_index_len(self):
        return self.esp_spi_lsb

    def seq_num_counter_len(self):
        return self.esp_sn_lsb

    def check_conf(self):
        if self.ehc_strategy == "NULL":
            self.esp_align = 4
            self.esp_spi_lsb = 4
            self.esp_sn_lsb = 4
            self.tcp_urgent = "uncompress"
            self.tcp_options = "uncompress"
            self.tcp_sn_lsb = 4

EHC_ESPHeader = Struct(
    "sec_param_index" / Bytes(this._.spi_len),
    "seq_num_counter" / Bytes(this._.sn_len) 
)

EHC_ClearTextESPPayload = Struct(
     "data" / Bytes(this._.data_len),
     "pad" / IfThenElse(this._.has_pad, Bytes(this._.pad_len), Const(b'')),
     "pad_len" / IfThenElse(this._.has_pad, Int8ub, Const(b'')),
     "next_header" / IfThenElse(this._.has_next_header, NextHeader, Const(b''))
)

EHC_ClearTextESP = Struct(
Embedded(EHC_ESPHeader),
Embedded(EHC_ClearTextESPPayload)
)

EHC_EncryptedESP = Struct(
Embedded(EHC_ESPHeader),
Embedded(EncryptedESPPayload)
)

 

class EHC_ESP(ESP):
    def __init__(self, sa):
        super().__init__(sa)
        if self.sa.mode == "tunnel" or self.sa.next_layer_proto != "ANY":
            self.has_next_header = False
        else:
            self.has_next_header = True
        if self.sa.esp_align == 1:
             self.has_pad = False
        else:
             self.has_pad = True



    def pack_pre_esp(self, data):
        return data

    def pack_esp(self, esp_payload):
        if self.has_next_header == False:
             esp_payload['next_header'] = b''
        if self.has_pad == False:
             esp_payload['pad_len'] = b''
             esp_payload['pad'] = b''
        data_len = len(esp_payload['data']) 
        pad_len = esp_payload['pad_len'] 
         
        return EHC_ClearTextESPPayload.build(esp_payload,\
                   data_len=data_len, pad_len=pad_len, \
                   has_pad=self.has_pad, \
                   has_next_header=self.has_next_header)

    def unpack_pre_esp(self, data):
       return data

    def unpack_esp(self, byte_payload):
        """
        Note that the function is focused on the decompression to
        handle the process to the traditional ESP stack. Other
        alternative could also include, extracting the data using the
        EHC_ClearTextESP structure. Instead we map to the ClearTextESPPayload
        structure.  
        """
        if self.has_next_header == False:
            if self.sa.mode == "tunnel":
                if self.sa.ts_ip_version() == 4:
                    next_header = NextHeader.build('IPv4')
                elif self.sa.ts_ip_version() == 6:
                    next_header = NextHeader.build('IPv6')
            elif self.next_layer_proto != "ANY":
                next_header = Int8ub.build(NextHeader.build(self.next_layer_proto))
            byte_payload += next_header
        next_header = Int8ub.build(byte_payload[-1])

        if self.sa.esp_align == 1:
            data = byte_payload[:-1]
        else:
            data = byte_payload[:len(byte_payload) - 2 - int(byte_payload[-2])]
             
        pad = self.pad(len(data), - (len(data) + 2) % 4 )
        pad_len = Int8ub.build(len(pad))
        return data + pad + pad_len + next_header

    def unpack_post_esp(self, encrypted_pkt):
        encrypted_pkt['sec_param_index'] = self.sa.sec_param_index  
        encrypted_pkt['seq_num_counter'] = self.sa.get_seq_num_counter(4) 
        return encrypted_pkt
         

    def to_bytes(self, encrypted_esp_pkt):
        encrypted_payload_len = len(encrypted_esp_pkt['encrypted_payload'])
        return EHC_EncryptedESP.build(encrypted_esp_pkt,\
                   spi_len=self.sa.sec_param_index_len(), \
                   sn_len=self.sa.seq_num_counter_len(), \
                   encrypted_payload_len=encrypted_payload_len, \
                   icv_len=self.sa.icv_len())


    def from_bytes(self, byte_encrypted_esp_pkt):
        spi_len = self.sa.sec_param_index_len() 
        sn_len = self.sa.seq_num_counter_len()
        encrypted_payload_len = len(byte_encrypted_esp_pkt) - spi_len -\
                                sn_len - self.sa.icv_len()
        return EHC_EncryptedESP.parse(byte_encrypted_esp_pkt, \
                   spi_len=spi_len, sn_len=sn_len, \
                   encrypted_payload_len=encrypted_payload_len, \
                   icv_len=self.sa.icv_len())
