"""Enable ``python .github/scripts/call_remote_executor`` invocation."""

import sys
import os

# When invoked as ``python .github/scripts/call_remote_executor``, Python
# sets __main__'s __package__ to None and relative imports fail.  Ensure the
# parent directory (`.github/scripts/`) is on sys.path so that the package
# can be imported by name, then use an absolute import.
if __package__ is None or __package__ == "":
    _parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    from call_remote_executor.cli import main
else:
    from .cli import main

main()
