import os
from osv.modules.api import *
from osv.modules.filemap import FileMap
from osv.modules import api

_module = '${OSV_BASE}/modules/vrdma-ulibs/libibverbs'

usr_files = FileMap()
usr_files.add(os.path.join(_module, 'libibverbs.so.1.0.0')).to('/usr/lib/libibverbs.so.1.0.0')
usr_files.add(os.path.join(_module, 'libibverbs.so.1')).to('/usr/lib/libibverbs.so.1')
usr_files.add(os.path.join(_module, 'libibverbs.so')).to('/usr/lib/libibverbs.so')
usr_files.add(os.path.join(_module, 'ibv_devinfo.so')).to('/tools/ibv_devinfo.so')
usr_files.add(os.path.join(_module, 'include/infiniband/')).to('/usr/include/infiniband/')
