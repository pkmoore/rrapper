"""
<Started>
  July 2018

<Author>
  Alan Cao

<Purpose>
  Incorporate module-wide configuration paths within a file.

  This file simply stores module-wide configuration constants that are used throughout
  rrinit, rrtest, and rreplay.

"""

import os

DEFAULT_CONFIG_PATH = str(os.path.dirname(os.path.expanduser("~") + "/.crashsim/")) + "/"
RR_TEST_CONFIG_PATH = str(os.path.dirname(os.path.expanduser("~") + "/.local/share/rr/")) + "/"

STRACE_DEFAULT = "strace_out.strace"

