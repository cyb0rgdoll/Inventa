import sys
from recon import osint as _impl

sys.modules[__name__] = _impl
