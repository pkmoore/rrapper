"""
<Program Name>
  crashsim

<Started>
  June 2019

<Author>
  Junjie Ge

<Purpose>
  A shorter command aimed to replace rrtest and rreplay in order to improve user experience

"""

import sys
import argparse
import subprocess
import logging

def main():
  # initialize parser
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers()

  # two commands - create / configure
  test_name = subparsers.add_parser(sys.argv[1])

  # ./rrtest create -n testname -c "./runthisbinary"
  test_name.set_defaults(cmd=sys.argv[1])
  test_name.add_argument('-m', '--mutator',
                               dest='mutator',
                               help='mutator to use')
  test_name.add_argument('-c', '--command',
                            dest='command',
                            help='specify command for rrtest')
  # test_name.add_argument('-f', '--force',
  #                           dest='force',
  #                           help='force overwrite creation of the test')

  # general flags to be set
  parser.add_argument('-v', '--verbosity',
                      dest='verbosity',
                      action='store_const',
                      const=logging.debug,
                      help='flag for displaying debug information')

  # parse arguments
  args = parser.parse_args()

  # configure logger
  logging.basicConfig(level=args.verbosity)

  # initialize actual application logic 
  man_options = ['command']
  for opt in man_options:
    if not args.__dict__[opt]:
      parser.print_help()
      sys.exit(1)

# I'm not sure if this is necessary, the code below this works fine. Commented out for now.

#   proc = subprocess.Popen(["rrtest", "create", "--name", args.cmd, "--command", args.command],stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess_flags)
#   proc.wait()
#   (stdout, stderr) = proc.communicate()

#   if proc.returncode != 0:
#     print(stderr)
#   else:
#     subprocess.call(["rrtest", "configure", "--name", args.cmd, "--mutator", args.mutator]) 

  subprocess.call(["rrtest", "create", "--name", args.cmd, "--command", args.command, "-f", "YES"])
  subprocess.call(["rrtest", "configure", "--name", args.cmd, "--mutator", args.mutator])

if __name__ == "__main__":
  main()