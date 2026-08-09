import sys
from scanning.tools import smap_scan as _impl

sys.modules[__name__] = _impl
