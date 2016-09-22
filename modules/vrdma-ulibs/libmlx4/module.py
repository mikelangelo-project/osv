import os
from osv.modules.api import *
from osv.modules.filemap import FileMap
from osv.modules import api

_module = '${OSV_BASE}/modules/vrdma-ulibs/libmlx4'

usr_files = FileMap()
usr_files.add(os.path.join(_module, 'libmlx4-rdmav2.so')).to('/usr/lib/libmlx4-rdmav2.so')
usr_files.add(os.path.join(_module, 'libmlx4-rdmav2.so')).to('/usr/lib/libmlx4.so')
usr_files.add(os.path.join(_module, 'mlx4.driver')).to('/usr/etc/libibverbs.d/mlx4.driver')

default = ""
