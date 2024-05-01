import pyesp.h6

class SCHC( pyesp.h6.H6 ):
  
  def __init__( self, data=b'', packed=None ):
    self.header_type = "SCHC"
    if packed != None:
      self.unpack( packed )
    else:
      self.data = data

  def pack( self ):
    return self.data

  def unpack( self, data:bytes ):
    self.data = data
    return self.data  
