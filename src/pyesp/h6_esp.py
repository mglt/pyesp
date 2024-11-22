import binascii
import secrets

from construct.core import *
from construct.lib import *

from pyesp.sa import SA, Error
import pyesp.h6

"""
https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
https://construct.readthedocs.io/en/latest/meta.html

"""

Pad = GreedyRange(Byte)

CT = 0

ESPPayload = Struct( 
  "data" / Bytes(this._.data_len),
  "pad" / Bytes(this._.pad_len),
#  "pad_len" / Rebuild( Int8ub, len_(this.pad)),
  "pad_len" / Int8ub,
  "next_header" / pyesp.h6.NextHeaderType,
  "integrity" / Check(this.pad_len == len_(this.pad)),
)

EncryptedESP = Struct(
  "spi" / Bytes(4), 
  "sn" / Bytes(4),
  "encrypted_payload" / Bytes(this._.encrypted_payload_len),
  "icv" / Bytes(this._.icv_len)
)

## signed_payload contains encrypted and icv.
SignedESP = Struct(
  "spi" / Bytes(4), 
  "sn" / Bytes(4),
  "signed_payload" / Bytes(this._.signed_payload_len),
)


## only used to show
ClearTextESP = Struct(
  "_name" / Computed( "ClearTextESP" ),      
  "spi" / Bytes(4), 
  "sn" / Bytes(4),
  "payload" / Struct(
    "data" / Bytes(this._._.data_len),
    "pad" / Bytes(this._._.pad_len),
#    "pad_len" / Rebuild( Int8ub, len_(this.pad)),
    "pad_len" / Int8ub,
    "next_header" / pyesp.h6.NextHeaderType ),
  "icv" / Bytes(this._.icv_len)
)


class ESP:
    
  def __init__(self,\
    sa=None, 
    spi:bytes=secrets.randbits( 32 ), 
    sn=0, 
    pad_len=None,
    next_header='IPv6NoNxt',
    data=b'',
    encrypted_payload=None,
    signed_payload=None,
    icv=None, 
    packed=None ):

    self.header_type = 'ESP'
    self.struct = ClearTextESP
    self.esp_align = 4
    self.pad_len = pad_len  
    self.data = data
    self.next_header = next_header
    self.encrypted_payload = encrypted_payload
    self.signed_payload = signed_payload
    self.icv = icv
   
    
    if isinstance( icv, bytes ):
      self.icv_len = len( icv )
    else: 
      self.icv_len = None
    if sa is not None:  
      self.sa = sa
      self.spi = self.sa.spi
      self.sn = self.sa.sn
      self.icv_len = self.sa.icv_len()
    else: 
      self.sa = None  
      self.spi = spi
      self.sn = sn

    if packed is not None:
      self.unpack( packed )

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


  def build_pad(self, data=None ):
    """ establish pad based on data
    
    data may be specified to avoid self.data to be 
    built multiple times
    """
    if data is None:
      data = self.data
    if isinstance( data, bytes ) is False:
      data = self.data.pack()
    data_len = len( data )  
    if self.pad_len == None:
        self.pad_len = ( 2 - data_len)%self.esp_align
    if ( data_len + self.pad_len + 2 )%self.esp_align != 0:
        raise PadLenError({'data_len': data_len, 'pad_len':pad_len}, \
                          "32 bits alignment is not respected")
    return Pad.build(range( self.pad_len + 1)[1:]) 


#  def pack(self, data, pad_len=None, next_header="IPv6NoNxt", debug=False):
  def pack(self ):
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

    In the best case, sa is provided and data is encrypted 
    When there is no SA we cannot unpack and retrieve data. In that case, we try to pack without data and use either signed_payload or encrypted_payload.  
    """
    ## we do not have self.data in clear text.
    ## this happens when the packet is simply 
    ## received without context.
    #if self.data is None :
        #print("NOne Data")
    if self.data is None :
      if self.icv is not None and\
         self.encrypted_payload is not None:
        print("SA is none")
        encrypted_esp_payload = EncryptedESP.build(
          { "spi" : self.spi, 
            "sn" : self.sn,
             "encrypted_payload" : self.encrypted_payload,
             "icv" : self.icv }, \
        encrypted_payload_len = len( self.encrypted_payload ),\
        icv_len = len( self.icv ) )
        
      elif self.icv_len is None and \
         self.signed_payload is not None:
        encrypted_esp_payload = SignedESP.build( 
          { 'spi' : self.spi, 
            'sn' : self.sn, 
            'signed_payload' : self.signed_payload}, 
          signed_payload_len = len( self.signed_payload) )
      else:   
        #ESP Clear Text Compression
        # Use ESPClearTextKompressor to compress the clear-text ESP payload 
        if self.sa is None: 
        	return esp_payload 
        # Encrypt and digest using SA's ciphers 
        ciphers = self.sa.ciphers_obj() 
        if len(ciphers) == 1: 
        	self.encrypted_payload, self.icv = ciphers[0].encrypt_and_digest(esp_payload) 
        	self.icv_len = len(self.icv) 
        	
        encrypted_esp_payload = EncryptedESP.build( 
        	{'spi': self.sa.get_spi(), 
        	 'sn': self.sa.get_sn(), 
        	 'encrypted_payload': self.encrypted_payload, 
        	 'icv': self.icv}, 
        	encrypted_payload_len=len(self.encrypted_payload), 
        	icv_len=self.icv_len 
        )
        
      return encrypted_esp_payload
    ## we have self.data in clear text
    ## whenever possible update next_header according to self.data
    else:   
      if isinstance( self.data, bytes ) is False:
        self.next_header = self.data.header_type  
#        data = self.data.pack()
        ## SCHC compression
        if self.sa.ehc_pre_esp  is not None:
          ## we limit ourselves to UDP (just for now and will
          ## address all possible cases later). 
          ## We need to ensure there cannot be any confusion. 
          ## Probably we will have to exclude SCHC to be compressed.
          ## Maybe that case will not exist in the future as IP6 as 
          ## IP6 will automatically be SCHC by diet-ESP

          if isinstance( self.data, pyesp.ip6.IP6 ):
             
             
             if isinstance( self.data.payload, pyesp.udp.UDP ): 
              print("SA is not none")
              print("compressing udp header:", self.data.payload) 
              pre_esp_k = pyesp.openschc_k.UDPKompressor( self.sa.ehc_pre_esp )
              schc_udp = pyesp.schc.SCHC( data=pre_esp_k.schc( self.data.payload.pack() ) )
              
              #maryam
              print("SCHC OF UDP length:",len(schc_udp.pack()))
              #maryam
              
              self.data.header.next_header = 'SCHC' ## need to consider extensions (ipv6 next header = schc)
              self.data.payload = schc_udp  #The IPv6 has a compressed UDP inside it
              self.data.len = len( schc_udp.pack() ) ## to be check if that is the correct value

              
              if isinstance( self, pyesp.h6_esp.ESP ):
               #print("compressing ipv6 header:", self.data)
               ip6_compressor = pyesp.openschc_k.IP6Kompressor(self.sa.ehc_pre_esp)
               compressed_ipv6 = ip6_compressor.schc(self.data.pack())
               schc_ip6 = pyesp.schc.SCHC(data=compressed_ipv6)
               #print("schcipv6:", schc_ip6)
              
              
               print("Setting the next header of esp as schc and its data as schc packet")
               self.next_header = 'SCHC' ## need to consider extensions
               self.data = schc_ip6  #The ESP has a compressed IPv6 inside it
               self.data.len = len( schc_ip6.pack() ) ## to be check if that is the correct value
              


        #### SCHC IP6-UDP completed    

        #print("BEFORE1", self.data) which is an ipv6 object
        data = self.data.pack() #schc object byte array
        CT = 1
        #print("AFTER1", data) which is a binary value
      else: 
        data = self.data    
        
       
      if self.sa.ehc_clear_text_esp is not None:
       #if isinstance( self.data, ESP ): 
        print("AA Let's print cte")
        ## SCHC compression for esp next header
        clear_text_esp_k = pyesp.openschc_k.ESPClearTextKompressor(self.sa.ehc_clear_text_esp)
        esp_payload = clear_text_esp_k.schc(data)
        # Parse the compressed payload into SCHC format
        schc_payload = pyesp.schc.SCHC(data=esp_payload)
        
        
        self.next_header = 'SCHC'  # Update the next header to indicate SCHC is inside
        self.data = schc_payload
        self.data.len = len(schc_payload.pack())
        
        #### SCHC CTE completed    
        #print("BEFORE", data)
        data = self.data.pack() #schc object byte array
        #print("AFTER", data)
        #maryam
        print("ESP CT PACKED")
        print("SCHC OF Clear Text ESP length:",self.data.len)
        #maryam
 

           
      #else:
        #now add ESP padding
        pad = self.build_pad( data=data)
   
        #clear_text_esp_payload
        esp_payload = ESPPayload.build(\
          { 'data' : data,  #the [SCHC IIPv6 + SCHC UDP + data is stored here]
            'pad' : pad,
            'pad_len' : len( pad ),
            'next_header' : self.next_header },
             data_len=len( data ),
             pad_len=len( pad ) )

       
        
      if self.sa is None:
        return esp_payload
   
      ciphers = self.sa.ciphers_obj()
      if len(ciphers) == 1:
        self.encrypted_payload, self.icv = \
          ciphers[0].encrypt_and_digest( esp_payload )
        self.icv_len = len( self.icv )       
      encrypted_esp_payload = EncryptedESP.build(\
                {'spi' : self.sa.get_spi(),\
                 'sn' : self.sa.get_sn(),\
                 'encrypted_payload' : self.encrypted_payload, 
                 'icv' : self.icv }, \
                 encrypted_payload_len=len( self.encrypted_payload ),\
                 icv_len=self.icv_len )
      if self.sa.ehc_esp is not None:
        eesp_k = pyesp.openschc_k.EncryptedESPKompressor( self.sa.ehc_esp ) 
        print("ESP has an encrypted payload")
        #maryam print( f"encrypted_esp_payload: [{type(encrypted_esp_payload)}] {encrypted_esp_payload}" )
        encrypted_esp_payload = eesp_k.schc( encrypted_esp_payload )
        
        #maryam
        string_schc = binascii.hexlify(encrypted_esp_payload).decode()
        string_size = len(string_schc)
        byte_size = string_size // 2
        print("ESP Encrypted paylod length (SCHC format):",byte_size)
        
    return encrypted_esp_payload

  def unpack(self, packed:bytes ):
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
    ## clear_text_esp_payload
    if self.sa is None:
      #print("Empty ESP")
      # fields that cannot be decrypted are set to None 
      self.next_header = None 
      self.pad_len = None
      self.data = None
      self.icv = None
      signed_payload_len = len( packed ) - 8
      signed_esp = SignedESP.parse( packed, signed_payload_len=signed_payload_len )
      self.spi = signed_esp[ 'spi' ]
      self.sn = signed_esp[ 'sn' ]
      self.signed_payload = signed_esp[ 'signed_payload' ]
    else:
      ## UNSCHC ESP  
      print ("ESP Payload")
      if self.sa.ehc_esp is not None:
       if CT ==1:
        eesp_k = pyesp.openschc_k.EncryptedESPKompressor( self.sa.ehc_pre_esp ) #unschc spi and sa
        packed = eesp_k.unschc( packed )

      self.icv_len = self.sa.icv_len()
      payload_len = len( packed) - 8 - self.icv_len
      encrypted_esp = EncryptedESP.parse( packed, \
               encrypted_payload_len=payload_len, \
               icv_len=self.icv_len ) 
      self.spi = encrypted_esp[ 'spi' ]
      self.sn = encrypted_esp[ 'sn' ]
      self.icv = encrypted_esp[ 'icv' ]
      self.encrypted_payload = encrypted_esp[ 'encrypted_payload' ] 
      self.data = b''
      



      ciphers = self.sa.ciphers_obj()
      #print("Encrypted Payload:", binascii.hexlify(self.encrypted_payload))
      #print("ICV:", binascii.hexlify(self.icv))
      #print("Cipher Configuration:", ciphers[0])
      if len(ciphers) == 1: #AEAD
        pass
      ''' maryam_check   clear_text_esp_payload_bytes =\
            ciphers[0].decrypt_and_verify(\
              self.encrypted_payload, self.icv )
              '''
      if self.sa.ehc_clear_text_esp is not None:
       if CT ==1:
        print("decompressing clear text esp payload") #which is the schc of nxt.hdr
        ## unschc clear_text_esp_payload_bytes
        # Use ESPClearTextKompressor to decompress and parse the clear-text ESP payload 
        clear_text_esp_k = pyesp.openschc_k.ESPClearTextKompressor(self.sa.ehc_clear_text_esp)
        decompressed_payload = clear_text_esp_k.unschc(clear_text_esp_payload_bytes)
        esp_payload = ESPPayload.parse(decompressed_payload)
            
        # Extract and update ESP attributes
        self.data = esp_payload['data']
        self.pad_len = esp_payload['pad_len']
        self.next_header = esp_payload['next_header']
            
        # Validate padding length
        if len(esp_payload['pad']) != self.pad_len:
            raise ValueError(
                f"Padding length mismatch: Expected {self.pad_len}, got {len(esp_payload['pad'])}"
            )
        else:
            print("Clear-text ESP compression not configured")
            # Handle cases where ESP CT is not configured
            self.data = clear_text_esp_payload_bytes

        ''''clear_text_payload = self.clear_text_compressor.parse(clear_text_esp_payload_bytes) 
        self.next_header = clear_text_payload[0].get(('ESP.NXT', 1), self.next_header) 
        self.data = clear_text_payload[1] if clear_text_payload else None
        
      self.pad_len = clear_text_esp_payload_bytes[ -2 ] 
      data_len = len( clear_text_esp_payload_bytes ) - 2 - self.pad_len
       
      clear_text_esp_payload = ESPPayload.parse( \
                                 clear_text_esp_payload_bytes, 
                                 pad_len=self.pad_len, \
                                 data_len=data_len )
      self.next_header = clear_text_esp_payload[ 'next_header' ]
      self.pad = clear_text_esp_payload[ 'pad' ]
      data = clear_text_esp_payload[ 'data' ]
      '''
      #maryam code for unparsing schc over ip6
      #if self.next_header == 'SCHC' :
       # pre_esp_k = pyesp.openschc_k.IP6Kompressor(self.sa.ehc_pre_esp)
        #print("see what is data ", self.data )
       # print("see what is data payload", self.data.payload() )
       # print("see what is pack", self.data.payload.pack() )
       # ip6_bytes = pre_esp_k.unschc( self.data.payload.pack() )
       # self.data = pyesp.ip6.IP6( packed=ip6_bytes )
        #maryam
      if self.next_header == 'IPv6':
        #print("ipv6 next header after schc:",self.next_header.next_header)
        self.data = pyesp.ip6.IP6( packed=data )
        ## SCHC decompression. 
        ## We assume here that IPv6/SCHC(UDP) exists. 
        ## This may not exist in the future. 
        if self.sa.ehc_pre_esp  is not None:
          if self.data.header.next_header == 'SCHC': ## must be last extension
            pre_esp_k = pyesp.openschc_k.UDPKompressor( self.sa.ehc_pre_esp )
            udp_bytes = pre_esp_k.unschc( self.data.payload.pack() )
            self.data.header.next_header = 'UDP' ## must be last nh
            self.data.payload = pyesp.udp.UDP( packed=udp_bytes )
      elif self.next_header == 'UDP':
          self.data = pyesp.udp.UDP( packed=data )
      elif self.next_header == 'SCHC' :
        if self.sa.ehc_pre_esp  is not None:
          ## In that case it means that SCHC has been generated by ESP
          ## This means that if a SCHC packet is handled by ESP, ESP 
          ## does not proceed to any further compression. 
          ## In this section we have inner IP6 being compressed by SCHC.
          ## In transport it may be a UDP packet i fthe transport 
          ## is specified in the SA.
          ## if sa.transport == UDP:
          
          
          pre_esp_k = pyesp.openschc_k.UDPKompressor( self.sa.ehc_pre_esp )
          udp_bytes = pre_esp_k.unschc( self.data.payload.pack() )
          self.data = pyesp.udp.UDP( packed=udp_bytes )
          
      else: 
        #self.data = data   
        pass


  def show( self ):
    """Display the Generic Header Extention

    ESP has its own show function as some parameters 
    MUST be passed to the parse function.
    This show mostly works as if no encryption occurs.

    """
    ## mostly to ensure we have the value for icv 
    ## / icv_len
    if self.icv == None:
      encrypted_packed = self.packed = self.pack( )
      self.unpack( encrypted_packed )
    ## without self.data we cannot display the clear text
    if self.data is None:
      if self.encrypted_payload is not None and\
        self.icv is not None:
        packed = EncryptedESP.build(
          { "spi" : self.spi, 
            "sn" : self.sn,
             "encrypted_payload" : self.encrypted_payload,
             "icv" : self.icv }, \
        encrypted_payload_len = len( self.encrypted_payload ),\
        icv_len = len( self.icv ) )
        unpacked = EncryptedESP.parse( packed, 
          encrypted_payload_len = len( self.encrypted_payload ),\
          icv_len = len( self.icv ) )
      elif self.signed_payload is not None:
        packed = SignedESP.build( 
          { 'spi' : self.spi, 
            'sn' : self.sn, 
            'signed_payload' : self.signed_payload}, 
          signed_payload_len = len( self.signed_payload) )
        unpacked = SignedESP.parse( packed, \
          signed_payload_len = len( self.signed_payload) )
      else:
        raise ValueError( "unable to display ESP without data" )
    ## we show the clear text     
    else:    
      data = self.data
      if isinstance( self.data, bytes ) is False:
        data = self.data.pack()
      data_len = len( data ) 
      pad = self.build_pad( data=data)
      pad_len = len( pad )
      ## only used to show
      packed = ClearTextESP.build( 
              { "spi" : self.spi, 
                "sn" : self.sn,
                "payload" : {\
                  'data' : data,
                  'pad' : pad,
                  'pad_len' : pad_len,
                  'next_header' : self.next_header },
                "icv" :self.icv }, \
                data_len=data_len, pad_len=pad_len,\
                icv_len=self.icv_len )
   
      unpacked = ClearTextESP.parse(\
              packed,
              data_len=data_len,
              pad_len=pad_len, 
              icv_len=self.icv_len )  
      print( f"## {unpacked._name} ##" )
      print( unpacked )
      print( "binary (encrypted ESP):" )
      print( binascii.hexlify( encrypted_packed, sep=' ' ) )
#      print( "\n" )

