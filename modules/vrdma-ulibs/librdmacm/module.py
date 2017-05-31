import os
from osv.modules.api import *
from osv.modules.filemap import FileMap
from osv.modules import api

_module = '${OSV_BASE}/modules/vrdma-ulibs/librdmacm'

usr_files = FileMap()
usr_files.add(os.path.join(_module, 'librdmacm.so.1.0.0')).to('/usr/lib/librdmacm.so.1')
usr_files.add(os.path.join(_module, 'include/rdma')).to('/usr/include/rdma')
usr_files.add(os.path.join(_module, 'librspreload.so.1.0.0')).to('/usr/lib/librspreload.so.1.0.0')
usr_files.add(os.path.join(_module, 'librspreload.so.1')).to('/usr/lib/librspreload.so.1')
usr_files.add(os.path.join(_module, 'librspreload.so')).to('/usr/lib/librspreload.so')

default = ""
