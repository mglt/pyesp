from construct.core import *
from construct.lib import *

from sa import SA, Error

"""

https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
https://construct.readthedocs.io/en/latest/meta.html

"""
NextHeader = Enum(BytesInteger(1), 
    IPv4 = 6,
    TCP = 6,
    UDP = 17,
    IPv6 = 41,
    ESP = 50, 
    AH = 51, 
    NoNxt = 59,
    SCTP = 132
)


Pad = GreedyRange(Byte)

ESPHeader = Struct(
    "sec_param_index" / Bytes(4), 
    "seq_num_counter" / Bytes(4),
)

ClearTextESPPayload = Struct( 
     "data" / Bytes(this._.data_len),
     "pad" / Bytes(this._.pad_len),
#     "pad_len" / Rebuild( Int8ub, len_(this.pad)),
     "pad_len" / Int8ub,
     "next_header" / NextHeader,
     "integrity" / Check(this.pad_len == len_(this.pad)),
)

ClearTextESP = Struct(
Embedded(ESPHeader),
Embedded(ClearTextESPPayload)
)

EncryptedESPPayload = Struct(
    "encrypted_payload" / Bytes(this._.encrypted_payload_len),
    "icv" / Bytes(this._.icv_len)
)

EncryptedESP = Struct(
Embedded(ESPHeader),
Embedded(EncryptedESPPayload)
)

class PadLenError(Error):
    """ Unsupported Encryption Algorithm Error """
    pass

class LsbError(Error):
    """Unable to take LSB bytes """

class ESP:
    
    def __init__(self, sa):
        self.sa = sa
        self.esp_align = 4
#        self.esp_sn_lsb = 4

    def lsb(self, param , lsb_len):
        """ return the least significant bytes

        Args:
            param (bytes, int): a number or a byte stream

        Return:
            lsb_param (bytes, int) the corresponding lsb
        """
        if lsb_len == 0:
            return b''
        return param[-lsb_len:]

    def encrypt_and_digest(self, bytes_data):
        """ encrypts bytes_data and returns encrypted_payload and icv

        Args:
            bytes_data (bytes): data to be encrypted

        Returns:
            encrypted_payload (bytes): the corresponding encrypted data
            icv, the icv
 
        This function initiates a cipher object for every packet. In
            fact, the object has to be instantiated for each nonce. In
            addition, encryption and decryption is not expected to be
            performed by different nodes, so different objects.   
        """
        ciphers = self.sa.ciphers_obj()
        if len(ciphers) == 1:
            return ciphers[0].encrypt_and_digest(bytes_data)

    def decrypt_and_verify(self, payload):
        """ decrypt data from encrypted_dats and icv

        Args:
            payload (dict): with encrypted_payload and icv. The ESP payload
                or ESP packet can be used. 
        Returns:
            data (bytes): the decrypted data.
        """

        ciphers = self.sa.ciphers_obj()
        if len(ciphers) == 1: #AEAD
            data = ciphers[0].decrypt_and_verify(\
                   payload['encrypted_payload'], payload['icv'])
        return data


    def pad(self, data_len, pad_len=None):
        if pad_len == None:
            pad_len = ( 2 - data_len)%self.esp_align
        if (data_len + pad_len + 2) %self.esp_align != 0:
            raise PadLenError({'data_len': data_len, 'pad_len':pad_len}, \
                              "32 bits alignment is not respected")
        return Pad.build(range(pad_len + 1)[1:]) 


    def pack(self, data, pad_len=None, next_header="NoNxt"):
        """ Generates an ESP encrypted packet

        Args:
            data (bytes): the data field of the ESP packet
            pad_len (int): the pad length (<255). Default value is None
                so pad_len is computed as the minimal value that provides
                32 bit alignment  
        Returns:
            encrypted_pkt (dict): the dictionary representing the ESP
                packet: {'sec_param_index':spi, 'seq_num_counter':sn,\
                          'encrypted_payload':ep, 'icv':icv}

        """
        data = self.pack_pre_esp(data)
        
        pad = self.pad(len(data), pad_len)
        byte_payload = self.pack_esp({'data':data, 'pad':pad,\
                            'pad_len':len(pad), \
                            'next_header':next_header})
        encrypted_payload, icv = self.encrypt_and_digest(byte_payload)
        return self.pack_post_esp(\
                  {'sec_param_index':self.sa.get_sec_param_index(),\
                   'seq_num_counter':self.sa.get_seq_num_counter(),\
                   'encrypted_payload':encrypted_payload, 'icv':icv})

    def pack_pre_esp(self, data):
        """ Preprocesses data before ESP encapsulation

        These functions have been placed in order to enable the
        enrichment of ESP. EHC is one example. 

        Args:
            data (dict/bytes): the data to be formated. When a
                structure is provided, the data needs to be converted 
                to bytes. 
        Returns:
            data (bytes): data to encapsulated
        """
        return data

    def pack_esp(self, esp_payload):
        """ Process the ESP payload 

        These functions have been placed in order to enable the
        enrichment of ESP. EHC is one example. 

        Args:
            esp_payload (dict): structure representing the ESP payload

        Returns:
            esp_payload (dict): structure representing the ESP payload
        """
        print("pack_esp: esp_payload: %s"%esp_payload)
        data_len =len(esp_payload['data'])
        pad_len = esp_payload['pad_len']
        return ClearTextESPPayload.build(esp_payload,\
                            data_len=data_len, pad_len=pad_len)

    def pack_post_esp(self, encrypted_pkt):
        """ Process the encrypted ESP packet

        These functions have been placed in order to enable the
        enrichment of ESP. EHC is one example. 

        Args:
            encrypted_esp_pkt (dict): the structure of an encrypted ESP packet

        Returns:
            encrypted_esp_pkt (dict): the structure of an encrypted ESP packet
        """
        return encrypted_pkt

    def unpack(self, encrypted_pkt):
        """ Returns the clear text data of an ESP encrypted packet

        unpack reverses the pack function. In fact encrypted_pkt may be
        limited to a dictionary with the keys 'encrypted_payload' and 
        'icv' as only these keys are used. 

        Args:
            encrypted_pkt (dict): a dictionary with keys:
                'encrypted_payload' and 'icv'           
        Returns:
            data (bytes): the data in clear text.

        """
        encrypted_pkt = self.unpack_post_esp(encrypted_pkt)
        byte_payload = self.decrypt_and_verify( \
                           encrypted_pkt)
        byte_payload = self.unpack_esp(byte_payload)
        pad_len = byte_payload[-2]
        data_len = len(byte_payload) - 2 - pad_len
        payload = ClearTextESPPayload.parse(byte_payload, pad_len=pad_len,\
                                            data_len=data_len)
        return payload

    def unpack_post_esp(self, encrypted_pkt):
        return encrypted_pkt

    def unpack_esp(self, byte_payload):
        return byte_payload

    def unpack_pre_esp(self, byte_data):
        return data

    def to_bytes(self, encrypted_esp_pkt):
        """ Converts an encrypted ESP packet structure to bytes

        Args:
            encrypted_esp_pkt (dict): structure of an ESP packet

        Returns:
           byte_encrypted_Esp_pkt (bytes): byte stream corresponding to
               the ESP packet        

        Todo:
            include the length computation in the structure.
        """
        
        encrypted_payload_len = len(encrypted_esp_pkt['encrypted_payload'])
        return EncryptedESP.build(encrypted_esp_pkt,\
                   encrypted_payload_len=encrypted_payload_len, \
                   icv_len=self.sa.icv_len()) 

    def from_bytes(self, byte_encrypted_esp_pkt):
        """ Converts an encrypted ESP packet from bytes to structure 

        Converts (encrypted) ESP packet from an byte representation
        to a dict structure

        Args:
            byte_encrypted_esp_pkt (bytes): byte representation of an
                encrypted ESP packet

        Returns:
            encrypted_esp_pkt (dict): structure representation of an
                encrypted ESP packet.
 
        Todo:
            include the length computation in the structure.
        """
        encrypted_payload_len = len(byte_encrypted_esp_pkt) - 8 - \
                                self.sa.icv_len() 
        return EncryptedESP.parse(byte_encrypted_esp_pkt, \
                   encrypted_payload_len=encrypted_payload_len, \
                   icv_len=self.sa.icv_len())
        

    def show(self, pkt, structure):
        if structure not in [ESPHeader, ClearTextESPPayload, ClearTextESP,\
                         EncryptedESPPayload, EncryptedESP]:
            raise Error(structure, "unknown structure")
        if isinstance(pkt, dict):
               print(structure.parse(structure.build(pkt)))
        else:
               print(structure.parse(pkt))     
 

   
