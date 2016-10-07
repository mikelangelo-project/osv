import os
from osv.modules.api import *
from osv.modules.filemap import FileMap
from osv.modules import api

_module = '${OSV_BASE}/modules/vrdma-ulibs/libmlx4'

usr_files = FileMap()
usr_files.add(os.path.join(_module, 'libmlx4-rdmav2.so')).to('/usr/lib/libibverbs/libmlx4-rdmav2.so')
usr_files.link(os.path.join(_module, '/usr/lib/libmlx4.so')).to('/usr/lib/libibverbs/libmlx4-rdmav2.so')
usr_files.add(os.path.join(_module, 'mlx4.driver')).to('/etc/libibverbs.d/mlx4.driver')

default = ""
