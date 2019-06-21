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
from rrtest import create_test, configure_test, list_test, pack_test, analyze_test 
from rreplay import call_replay

def main():
  # initialize parser
  parser = argparse.ArgumentParser()
  subparser = parser.add_subparsers(metavar='MYTEST', help='name of test')


  # if no arguments given
  try:
    sys.argv[1]
  except:
    parser.print_help()
    sys.exit(1)

  if sys.argv[1] == "-h":
    parser.print_help()
    sys.exit(1)

  test_name = subparser.add_parser(sys.argv[1])

  # setting necessary flags
  test_name.set_defaults(cmd=sys.argv[1])
  test_name.add_argument('-m', '--mutator',
                               dest='mutator',
                               required=True,
                               help='mutator to use',
                               nargs='+')
  test_name.add_argument('-c', '--command',
                               dest='command',
                               required=True,
                               help='specify command for rrtest')
  test_name.add_argument('-f', '--force',
                               dest='force',
                               default='YES',
                               help='force overwrite creation of the test')

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

  # creating the test
  logging.debug("----------creating test----------")
  create_test(args.cmd, args.command, args.force, args.verbosity)

  # configuring the test
  logging.debug("----------configuring test----------")
  configure_test(args.cmd, args.mutator, args.verbosity)
  
  # replay the test
  logging.debug("----------replaying test----------")
  call_replay(args.cmd, args.verbosity)

if __name__ == "__main__":
  main()
  sys.exit(0)
