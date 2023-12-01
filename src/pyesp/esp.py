import binascii

from construct.core import *
from construct.lib import *

from pyesp.sa import SA, Error

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

ESPPayload = Struct( 
  "data" / Bytes(this._.data_len),
  "pad" / Bytes(this._.pad_len),
#  "pad_len" / Rebuild( Int8ub, len_(this.pad)),
  "pad_len" / Int8ub,
  "next_header" / NextHeader,
  "integrity" / Check(this.pad_len == len_(this.pad)),
)

EncryptedESP = Struct(
  "spi" / Bytes(4), 
  "sn" / Bytes(4),
  "encrypted_payload" / Bytes(this._.encrypted_payload_len),
  "icv" / Bytes(this._.icv_len)
)

class ESP:
    
  def __init__(self, sa):
    self.sa = sa
    self.esp_align = 4

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


  def pack(self, data, pad_len=None, next_header="NoNxt", debug=False):
    """ Generates an ESP encrypted packet

    Args:
        data (bytes): the data field of the ESP packet
        pad_len (int): the pad length (<255). Default value is None
            so pad_len is computed as the minimal value that provides
            32 bit alignment  
    Returns:
        encrypted_pkt (dict): the dictionary representing the ESP
            packet: {'spi':spi, 'sn':sn,\
                      'encrypted_payload':ep, 'icv':icv}

    """
    esp_payload_data, next_header = self.pack_esp_payload_data( data )
    
    clear_text_esp_payload = self.pack_clear_text_esp_payload(\
                               esp_payload_data, \
                               pad_len=pad_len, \
                               debug=debug )

    return self.pack_encrypted_esp( clear_text_esp_payload,\
                                       debug=debug )

  def pack_esp_payload_data( self, data ):
    """ Preprocesses data before ESP encapsulation

    These functions have been placed in order to enable the
    enrichment of ESP. EHC is one example. 

    Args:
        data (dict/bytes): the data to be formated. When a
            structure is provided, the data needs to be converted 
            to bytes. 
    Returns:
        data (bytes): data to encapsulated
        next_header (str): the type of data (IPv6, UDP,TCP, 
          or "NoNxt" (default)
    """

    # if SA mentions port compression
    # if UDP Packet 

    # if TCP packet 

    ## compress openSCHC 
    ## return bytes
    next_header="NoNxt"
    return data, next_header


  def pack_clear_text_esp_payload(self, esp_payload_data:bytes, \
                                   next_header="NoNxt", \
                                   pad_len=None, debug=False ) -> bytes :
    """ Process the ESP payload 

    These functions have been placed in order to enable the
    enrichment of ESP. EHC is one example. 

    Args:
        esp_payload (dict): structure representing the ESP payload

    Returns:
        esp_payload (dict): structure representing the ESP payload
    """
    pad = self.pad( len( esp_payload_data ), pad_len=pad_len )
    clear_text_esp_payload = {\
      'data' : esp_payload_data, \
      'pad' : pad, \
      'pad_len' : len( pad ), \
      'next_header' : next_header }
    esp_payload = ESPPayload.build(\
                    clear_text_esp_payload,\
                    data_len=len( esp_payload_data ),\
                    pad_len=len( pad ) )
    if debug is True :
      print( "\n## ESP Payload :" )
      print( ESPPayload.parse( esp_payload, \
                        data_len=len( esp_payload_data ), 
                        pad_len=len( pad ) ) )
      print( "binary:" )
      print( binascii.hexlify( esp_payload ) )

#    ## SCHC compression 
#    if schc is True :
#      print( "compressed ESP Payload :" )

    return esp_payload

  def pack_encrypted_esp(self, clear_text_esp_payload:bytes, debug=False )-> bytes:
    """ Process the encrypted ESP packet

    These functions have been placed in order to enable the
    enrichment of ESP. EHC is one example. 

    Args:
        encrypted_esp_pkt (dict): the structure of an encrypted ESP packet

    Returns:
        encrypted_esp_pkt (dict): the structure of an encrypted ESP packet
    """
    ciphers = self.sa.ciphers_obj()
    if len(ciphers) == 1:
      encrypted_payload, icv = \
        ciphers[0].encrypt_and_digest( clear_text_esp_payload )
             
    encrypted_esp = EncryptedESP.build(\
              {'spi':self.sa.get_spi(),\
               'sn':self.sa.get_sn(),\
               'encrypted_payload':encrypted_payload, 'icv':icv}, \
               encrypted_payload_len=len( encrypted_payload ),\
               icv_len=len( icv ) )

    if debug is True :
      print( "\n## Encrypted ESP:" )
      icv_len = self.sa.icv_len()
      payload_len = len(encrypted_esp) - 8 - icv_len
      print( EncryptedESP.parse( encrypted_esp, \
               encrypted_payload_len=payload_len, \
               icv_len=icv_len ) ) 
      print( "binary:" )
      print( binascii.hexlify( encrypted_esp ) )

#    ## SCHC compression 
#    if schc is True :
#      print( "compressed ESP Payload :" )
    return encrypted_esp 

  def pack_ip( self, encrypted_esp:bytes, debug=False )-> bytes:
    return ip_esp


  def unpack(self, ip_esp:bytes, debug:bool=False ):
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
    encrypted_esp = self.unpack_encrypted_esp( ip_esp, debug=debug )

    clear_text_esp_payload = self.unpack_clear_text_esp_payload( encrypted_esp, debug=debug )     

    esp_data = self.unpack_esp_payload_data( clear_text_esp_payload, debug=debug )

    return esp_data

  def unpack_encrypted_esp(self, ip_esp:bytes, debug=False ):
    return ip_esp

  def unpack_clear_text_esp_payload(self, encrypted_esp:bytes, debug=False):
    if debug is True:
      print( "\n## Encrypted ESP:" )
      print( "binary:" )
      print( binascii.hexlify( encrypted_esp ) )

    icv_len = self.sa.icv_len()
    payload_len = len(encrypted_esp) - 8 - icv_len
    encrypted_esp = EncryptedESP.parse( encrypted_esp, \
             encrypted_payload_len=payload_len, \
             icv_len=icv_len ) 
    if debug is True:
      print( f"\n{encrypted_esp}" )

    ciphers = self.sa.ciphers_obj()
    if len(ciphers) == 1: #AEAD
        clear_text_esp_payload = ciphers[0].decrypt_and_verify(\
               encrypted_esp['encrypted_payload'],\
               encrypted_esp['icv'] )
    return clear_text_esp_payload

  def unpack_esp_payload_data(self, clear_text_esp_payload:bytes, debug=False )->bytes:

    if debug is True:
      print( "\n## ESP Payload :" )
      print( "binary:" )
      print( binascii.hexlify( clear_text_esp_payload ) )

    pad_len = clear_text_esp_payload[ -2 ] 
    data_len = len( clear_text_esp_payload ) - 2 - pad_len
    
    clear_text_esp_payload = ESPPayload.parse( \
                               clear_text_esp_payload, 
                               pad_len=pad_len, \
                               data_len=data_len )
    if debug is True:
      print( clear_text_esp_payload )

    return clear_text_esp_payload[ 'data' ]

