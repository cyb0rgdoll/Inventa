import sys
from scanning.tools import zmap_scan as _impl

sys.modules[__name__] = _impl
