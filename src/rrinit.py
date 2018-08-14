#!/usr/bin/env python2.7
"""
<Program Name>
  rrinit

<Started>
  July 2018

<Author>
  Alan Cao

<Purpose>
  Executes initialization routines for the creation of a CrashSimulator
  environment.

  Before the user can create any tests and perform a record-replay
  execution, the testing environment must be optimal for such use. This
  application-level script checks for an optimal microarchitecture,
  update necessary proc entries, creates a path for storing tests and
  configs, and also generates the necessary syscall_definitions.pickle
  file.

  By running `rrinit`, a lot of the work can be taken out of `rrtest`
  and `rreplay`, and users are able to catch environmental anomalies
  before execution.

"""

import os
import sys
import subprocess
import argparse
import logging

import cpuid
import consts
import parse_syscall_definitions

def main():
    
    # initialize parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--generate', 
                        dest='generate', 
                        action='store_true',
                        help='(re)generate syscall_definitions.pickle file')
    parser.add_argument('-v', '--verbosity',
                        dest='loglevel',
                        action='store_const',
                        const=logging.DEBUG,
                        help='flag for displaying debug information')
     
    # parse arguments
    args = parser.parse_args()    

    # add simple logging for verbosity
    logging.basicConfig(level=args.loglevel)

    # check CPUID environment
    logging.debug("Checking CPU architecture compatibility")
    if cpuid.cpuid_check() != 0:
        exit(1)

    # checking if disabled ASLR
    logging.debug("Checking if ASLR is disabled")
    with open('/proc/sys/kernel/randomize_va_space', 'r') as p:
        if p.read() == '1':
            print "ASLR should be disabled. \
            Set /proc/sys/kernel/randomize_va_space = 0"
            sys.exit(1)

    # checking if disabled ptrace on processes
    logging.debug("Checking if ptrace on processes is enabled")
    with open('/proc/sys/kernel/yama/ptrace_scope', 'r') as p:
        if p.read() == '1':
            print "ptrace on processes should be disabled \
            Set /proc/sys/kernel/yama/ptrace_scope = 0"
            sys.exit(1)

    # check to see if rr is a valid shell-level command.
    # error status is nonzero
    logging.debug("Checking if `rr` is a valid shell command")
    try:
        with open(os.devnull, 'w') as fnull:
            subprocess.check_call(['rr', 'help'],
                                 stdout=fnull,
                                 stderr=subprocess.STDOUT)
    # in the case that the command failed to execute for internal reasons
    except subprocess.CalledProcessError:
        print 'rr was found by "rr help" exited with an error.'
        sys.exit(1)
    # in the case that the command is not valid at all
    except OSError:
        print 'rr command is not found. Make sure it is installed and described within your $PATH'
        sys.exit(1)

    # create ~/.crashsim/
    if not os.path.exists(consts.DEFAULT_CONFIG_PATH):
        logging.debug("Creating configuration path")
        try:
            os.makedirs(consts.DEFAULT_CONFIG_PATH)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    # check for existence of rrdump pipe
    logging.debug("Checking if pipe already exists")
    if os.path.exists(consts.DEFAULT_CONFIG_PATH + "rrdump.pipe"):
        os.unlink(consts.DEFAULT_CONFIG_PATH + "rrdump.pipe")

    # generate pickle
    if not os.path.exists(consts.DEFAULT_CONFIG_PATH + "syscall_definitions.pickle"):
        print "syscall_definitions.pickle does NOT exist. Regenerating."
        parse_syscall_definitions.generate_pickle()         
    
    print "\n=========================================================="
    print "Sucessfully initialized CrashSimulator environment!"
    sys.exit(0)


if __name__ == '__main__':
    main()
