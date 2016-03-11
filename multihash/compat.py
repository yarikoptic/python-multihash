"""Python compatability."""

import sys

#: Python version check
PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3


if PY3:
    integer_types = int,

    def b(s):
        """Byte literal."""
        return s.encode("latin-1")

else:
    integer_types = (int, long)

    def b(s):
        """Byte literal."""
        return s
