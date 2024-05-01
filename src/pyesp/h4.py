
from construct import *
from construct.lib import *



IpAddress = ExprAdapter(Byte[4],
    decoder = lambda obj,ctx: "{0}.{1}.{2}.{3}".format(*obj),
    encoder = lambda obj,ctx: [int(x) for x in obj.split(".")],
)

