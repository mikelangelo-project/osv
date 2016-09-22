from osv.modules.api import *

_module = '${OSV_BASE}/modules/vrdma-ulibs'

require('vrdma-ulibs/libibverbs')
require('vrdma-ulibs/libmlx4')
require('vrdma-ulibs/librdmacm')

default = ""
