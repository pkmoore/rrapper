"""
<Program Name>
  consts

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


# represents folder where rrtest will create tests
DEFAULT_CONFIG_PATH = str(os.path.dirname(os.path.expanduser("~") + "/.crashsim/")) + "/"

# represents the folder where rr by default store its files
RR_TEST_CONFIG_PATH = str(os.path.dirname(os.path.expanduser("~") + "/.local/share/rr/")) + "/"

# represents the name of strace output files generated by rr
STRACE_DEFAULT = "strace_out.strace"

