"""
<Program Name>
util

<Purpose>
  This is the standard 'kitchen sink' file for this project.  Essentially,
  its a lazy place for me to put code that needs to be called from many other
  places.  Intiailly, a lot of these functions were copy-pasted around in
  different handler modules so we're at least better than that at this point...

"""


import binascii
import logging
import os
import signal
import sys
import time
import syscallreplay as cint

from errno_dict import ERRNO_CODES
from os_dict import OS_CONST
from syscall_dict import SOCKET_SUBCALLS
from syscall_dict import SYSCALLS


def process_is_alive(pid):
  """
  <Purpose>
    Return whether or not a process is alive.  If a process is alive, kill()
    with no signal (0) succeeds but doesn't do anything.  If the process isn't
    alive, an OSError is raised.

  """
  try:
    os.kill(int(pid), 0)
    return True
  except OSError:
    return False


def string_time_to_int(strtime):
  """
  <Purpose>
    Convert string time in strace format to an int

    Not Implemented:
    Microseconds are lost

  <Returns>
    time from the epoch in seconds as an int

  """

  if strtime == '0':
    logging.debug('Got zero st_atime')
    return 0
  else:
    logging.debug('Got normal st_atime')
    if '.' in strtime:
      strtime = strtime[:strtime.find('.')]
    return int(time.mktime(time.strptime(strtime, '%Y/%m/%d-%H:%M:%S')))


def stop_for_debug(pid):
    logging.debug('Stopping %d for debug', pid)
    os.kill(pid, signal.SIGSTOP)
    logging.debug('SIGSTOP sent')
    cint.detach(pid)
    logging.debug('ptrace detached')
    raise ReplayDeltaError('Process {} exited for debugging'.format(pid))


def dump_memory_to_file(pid, addr_start, addr_end, filename):
    with open(filename, 'wb') as f:
        data = cint.copy_address_range(pid, addr_start, addr_end)
        f.write(data)
        f.close()


def noop_current_syscall(pid):
  """
  <Purpose>
    No-op' out the current system call the child process is trying to
    execute by replacing it with a call to getpid() (a system call that takes
    no parameters and has no side effects).  Then, configure ptrace to allow
    the child process to run until it exits this call to getpid() and tell our
    own process to wait for this notification.  Set the entering flip-flip flag
    to to show that we are exiting a system call (because the child application
    now believes the system call it tried to make completed successfully).

    When this function is called from a handler, the handler needs to deal with
    setting up the output buffers and return value that the system call would
    have done itself had we allowed it to run normally.

    Note: This function leaves the child process in a state of waiting at the
    point just before execution returns to userspace code.

  <Returns>
    Nothing

  """

  logging.debug('Nooping the current system call in pid: %s', pid)
  # Transform the current system call in the child process into a call to
  # getpid() by poking 20 into ORIG_EAX
  cint.poke_register(pid, cint.ORIG_EAX, 20)
  # Tell ptrace we want the child process to stop at the next system call
  # event and restart its execution.
  cint.syscall(pid, 0)
  # Have our process monitor the execution of the child process until it
  # receives a system call event notification.  The notification we receive
  # at this point (if all goes according to plan) is the EXIT notification
  # for the getpid() call we forced the application to make.
  next_syscall()
  # Take a look at the current system call (i.e. the one that triggered the
  # notification we just received from ptrace).  It should be getpid().  If
  # it isnt, something has gone horribly wrong and we must bail out.
  skipping = cint.peek_register(pid, cint.ORIG_EAX)
  if skipping != 20:
    raise Exception('Nooping did not result in getpid exit. Got {}'
                    .format(skipping))
  # Because we are exiting the getpid() call so we need to set the entering
  # flip-flop flag to reflect this.  This allows later code (in main.py) to
  # set it BACK to entering before we begin processing the entry for the next
  # system call.
  cint.entering_syscall = False


def next_syscall():
  """
  <Purpose>
    Wait for the child process to pause at the next system call entry/exit.
    Returns whether or not there IS a next system call (or if the process
    actually exited)

  <Returns>
    True if there is a next system call available
    False if there is not another system call available
  """
  s = os.wait()
  if os.WIFEXITED(s[1]):
      return False
  return True


def extract_socketcall_parameters(pid, address, num):
  """
  <Purpose>
    Socket subcall parameters are passed as an array of integers of some
    length pointed to by the address in ECX at the time the socket_subcall
    system call is made.  This code picks them out and returns them as a list
    of integers.

  <Returns>
    List of socketcall parameters extracted from PID's memory at address

  """
  params = []
  for i in range(num):
      params += [cint.peek_address(pid, address)]
      address = address + 4
  logging.debug('Extracted socketcall parameters: %s', params)
  return params


def validate_syscall(syscall_id, syscall_object):
    """
    <Purpose>
      Validate a system call id to make sure it matches the name in the system
      call object.  This is essentially a fancy dictionary lookup made horrible
      by discrepencies in the way strace names system calls and the way our Linux
      kernel names them.

      TODO: reduce the number of hacks for name discrepancies somehow.

    <Returns>
      Nothing
    """

    # format system call from syscall_dict for comparison with parameters
    #   i.e sys_waitpid = waitpid
    compare_syscall = SYSCALLS[syscall_id][4:]

    # Alan: optimization for long and string-y if blocks for system call validation
    syscall_map_dict = {
        192: 'mmap',
        140: 'llseek',
        268: 'stat',
        199: 'getuid',
        200: 'getgid',
        201: 'geteuid',
        202: 'getegid',
        207: 'fchown',
        209: 'getresuid',
        211: 'getresgid',
        142: '_newselect',
    }

    for id, syscall_name in syscall_map_dict.iteritems():
        if syscall_id == id and syscall_name in syscall_object.name:
            return

    # HACK: Workaround for stat-lstat ambiguity
    if syscall_object.name == 'stat64' and compare_syscall == 'lstat64':
        raise ReplayDeltaError('System call validation failed: from '
                               'execution: {0}({1}) is not from '
                               'trace:{2}'
                               .format(compare_syscall,
                                       syscall_id,
                                       syscall_object.name))

    # syscall not valid if syscall_name doesn't match compare_syscall
    if syscall_object.name not in compare_syscall:
        raise ReplayDeltaError('System call validation failed: from '
                               'execution: {0}({1}) is not from '
                               'trace:{2}'
                               .format(compare_syscall,
                                       syscall_id,
                                       syscall_object.name))


def validate_subcall(subcall_id, syscall_object):
    """
    <Purpose>
      Validate the socket subcall id against the name in the system call
      object. Notice how there's no horrible hacks in here.

    <Returns>
      Nothing
    """

    # format socket call from syscall_dict for comparison with parameters
    #   i.e sys_socketpair = socket_pair
    compare_socketcall = SOCKET_SUBCALLS[subcall_id][4:]

    # socketcall not valid if syscall_name doesn't match compare_socketcall
    if syscall_object.name not in compare_socketcall:
        raise ReplayDeltaError('Subcall validation failed: from '
                               'execution: {0}({1}) is not from '
                               'trace:{2}'
                               .format(compare_socketcall,
                                       subcall_id,
                                       syscall_object.name))


def cleanup_return_value(val):
    '''Strace does some weird things with return values.  This function
    attempts to account for any weird things I've encountered.  Its purpose is
    to tranform whatever weird stuff strace gave us into an integer return
    value that can be poked into EAX at the end of a handler.
    '''
    if val == '?':
        logging.debug('Heads up! We\'re going to -1 for a "?" value')
        return -1
    if type(val) == type(list()):
        ret_val = list_of_flags_to_int(val)
    else:
        try:
            ret_val = int(val)
        except ValueError:
            logging.debug('Couldn\'t parse ret_val as base 10 integer')
            try:
                ret_val = int(val, base=16)
            except ValueError:
                logging.debug('Couldn\'t parse ret_val as base 16 either')
                try:
                    logging.debug('Trying to look up ret_val')
                    ret_val = OS_CONST[val]
                except KeyError:
                    logging.debug('Couldn\'t look up value from OS_CONST dict')
                    raise ValueError('Couldn\'t get integer form of return '
                                     'value!')
        logging.debug('Cleaned up value %s', ret_val)
    return ret_val


def list_of_flags_to_int(lof):
    '''Convert a list of flags (flags separated by |'s) into an integer value.
    This is accomplished by looking up the values given to the flag in our
    version of Linux and OR'ing them together (including any unnamed octal
    values)
    '''
    logging.debug('Parsing list of flags into an int')
    int_val = 0
    for i in lof:
        try:
            logging.debug('looking up value')
            tmp = OS_CONST[i]
        except KeyError:
            raise ValueError('Couldn\'t look up value ({}) from OS_CONST dict'
                             .format(i))
        logging.debug('Found value: %d', tmp)
        int_val = int_val | tmp
    logging.debug('Resultant int: %d', int_val)
    return int_val


def apply_return_conditions(pid, syscall_object):
    """
    <Purpose>
      Apply the return conditions described in the system call object to the
      current system call the child process is paused in.  This involves turning
      whatever madness strace gave as a return value into a suitable integer,
      transforming that integer to induce the correct errno value (if required),
      and poking that value into EAX.

      Note: For our Linux and glibc version, we return a value of the form:
          (-1 * <intended errno value>)
      in EAX.  Glibc recognizes this situation, sets errno to (-1 * EAX) and sets
          EAX to -1 thereby producing the "returns -1 on error with errno set
          correctly" behavior we know and love.
    <Returns>
      Nothing

    """

    logging.debug('Applying return conditions')
    ret_val = syscall_object.ret[0]
    # HACK: deal with the way strace reports flags in return values for fcntl
    if (syscall_object.name == 'fcntl64'
       and syscall_object.ret[0] == 'FD_CLOEXEC'):
        logging.debug('Got fcntl64 call, real return value is in ret[0]')
        ret_val = 0x1
    elif syscall_object.ret[0] == -1 and syscall_object.ret[1] is not None:
        logging.debug('Got non-None errno value: %s', syscall_object.ret[1])
        try:
            error_code = ERRNO_CODES[syscall_object.ret[1]]
        except KeyError:
            raise NotImplementedError('Unrecognized errno code: {}'
                                      .format(syscall_object.ret[1]))
        logging.debug('Looked up error number: %s', error_code)
        ret_val = -error_code
        logging.debug('Will return: %s instead of %s',
                      ret_val,
                      syscall_object.ret[0])
    else:
        ret_val = cleanup_return_value(ret_val)
    logging.debug('Injecting return value %s', ret_val)
    cint.poke_register(pid, cint.EAX, ret_val)


# Generic handler for all calls that just need to return what they returned in
# the trace.
# Currently used by send, listen
# TODO: check this guy for required parameter checking
def subcall_return_success_handler(syscall_id, syscall_object, pid):
    '''This probably should be here.  This badly named handler simply takes a
    socket subcall situation, validates the file descriptor involved, no-ops
    the call, and applies the return conditions from the system call object.
    For several socket calls, this is all that's required so we don't need to
    write individual handlers that all do the same thing.

    TODO: Move this to generic_handlers module
    TODO: Replace parameter extraction with call to
    extract_socketcall_parameters

    '''
    logging.debug('Entering subcall return success handler')
    if syscall_object.ret[0] == -1:
        logging.debug('Handling unsuccessful call')
    else:
        logging.debug('Handling successful call')
        ecx = cint.peek_register(pid, cint.ECX)
        logging.debug('Extracting parameters from address %s', ecx)
        params = extract_socketcall_parameters(pid, ecx, 1)
        fd = params[0]
        fd_from_trace = syscall_object.args[0].value
        logging.debug('File descriptor from execution: %s', fd)
        logging.debug('File descriptor from trace: %s', fd_from_trace)
        if fd != int(fd_from_trace):
            raise ReplayDeltaError('File descriptor from execution ({}) '
                                   'differs from file descriptor from trace'
                                   .format(fd, fd_from_trace))
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


class ReplayDeltaError(Exception):
    '''Rename Exception to ReplayDeltaError so we can be more descriptive when
    we need to raise an exception of this variety.
    '''
    pass


'''Below this point lies dragons... Beware! I'll get around to documenting this
   stuff eventually.  Ideally before I forget how all of it works!
   TODO: move file descriptor management stuff into its own module.
'''


def validate_integer_argument(pid,
                              syscall_object,
                              trace_arg,
                              exec_arg,
                              params=None,
                              except_on_mismatch=True):
    logging.debug('Validating integer argument (trace position: %d '
                  'execution position: %d)',
                  trace_arg,
                  exec_arg)
    # EAX is the system call number
    POS_TO_REG = {0: cint.EBX,
                  1: cint.ECX,
                  2: cint.EDX,
                  3: cint.ESI,
                  4: cint.EDI}
    if not params:
        arg = cint.peek_register(pid, POS_TO_REG[exec_arg])
    else:
        arg = params[exec_arg]
    arg_from_trace = int(syscall_object.args[trace_arg].value)
    logging.debug('Argument from execution: %d', arg)
    logging.debug('Argument from trace: %d', arg_from_trace)
    # Check to make sure everything is the same
    # Decide if this is a system call we want to replay
    if arg_from_trace != arg:
        message = 'Argument value at trace position: {}, ' \
                  'execution position: {} from execution  ({}) ' \
                  'differs argument value from trace ({})' \
                  .format(trace_arg, exec_arg, arg, arg_from_trace)
        _except_or_warn(message, except_on_mismatch)

def validate_address_argument(pid,
                              syscall_object,
                              trace_arg,
                              exec_arg,
                              params=None,
                              except_on_mismatch=True):
    logging.debug('Validating address argument (trace position: %d '
                  'execution position: %d)',
                  trace_arg,
                  exec_arg)
    if not params:
        arg = cint.peek_register(pid, _pos_to_reg(exec_arg))
    else:
        arg = params[exec_arg]
    # Convert signed interpretation from peek register to unsigned
    arg = arg & 0xffffffff
    if syscall_object.args[trace_arg].value == 'NULL':
        arg_from_trace = 0
    else:
        arg_from_trace = int(syscall_object.args[trace_arg].value, 16)
    if arg_from_trace != arg:
        message = 'Argument value at trace position: {}, ' \
                  'execution position: {} from execution  ({}) ' \
                  'differs argument value from trace ({})' \
                  .format(trace_arg, exec_arg, arg, arg_from_trace)
        _except_or_warn(message, except_on_mismatch)


def validate_return_value(pid, syscall_object, except_on_mismatch=True):
    ret_from_execution = cint.peek_register(pid, cint.EAX)
    ret_from_trace = cleanup_return_value(syscall_object.ret[0])
    if syscall_object.ret[1] is not None:
        logging.debug('We have an errno code')
        logging.debug('Errno code: %s', syscall_object.ret[1])
        errno_retval = -1 * ERRNO_CODES[syscall_object.ret[1]]
        logging.debug('Errno ret_val: %d', errno_retval)
        if errno_retval == ret_from_execution:
            return
    if ret_from_execution < 0:
        ret_from_execution &= 0xffffffff
    if ret_from_execution != ret_from_trace:
        message = 'Return value from execution ({}, {:02x}) differs ' \
                  'from return value from trace ({}, {:02x})' \
                  .format(ret_from_execution,
                          ret_from_execution,
                          ret_from_trace,
                          ret_from_trace)
    _except_or_warn(message, except_on_mismatch)


def _except_or_warn(message, except_on_mismatch):
    if except_on_mismatch:
        raise ReplayDeltaError(message)
    else:
        logging.warn(message)


def _pos_to_reg(pos):
    POS_TO_REG = {0: cint.EBX,
                  1: cint.ECX,
                  2: cint.EDX,
                  3: cint.ESI,
                  4: cint.EDI}
    return POS_TO_REG[pos]


def update_socketcall_paramater(pid, params_addr, pos, value):
    logging.debug('We are going to update a socketcall_parameter')
    LONG_SIZE = 4
    addr = params_addr + (pos * LONG_SIZE)
    logging.debug('Params addr: %x', params_addr)
    logging.debug('Specific parameter addr: %x', addr)
    value = int(value)
    logging.debug('Value: %d', value)
    cint.poke_address(pid, addr, value)
    logging.debug('Re-extracting socketcall parameters')
    p = extract_socketcall_parameters(pid, params_addr, pos + 1)
    if p[pos] != value:
        raise ReplayDeltaError('Populated socketcall parameter value: ({}) '
                               'was not updated to correct value: ({})'
                               .format(p[pos], value))


def find_arg_matching_string(args, arg_to_find):
  args_found = []
  for arg_index, arg_value in enumerate(args):
    arg_value.value = arg_value.value.strip('{}')
    if arg_to_find == arg_value.value[:arg_value.value.rfind('=')]:
      args_found.append((arg_index, arg_value.value))
  if len(args_found) > 1:
    import pdb
    pdb.set_trace()
    raise ReplayDeltaError('Found more than one arg for specified string '
                           '({}) ({})'.format(args_found, arg_to_find))
  return args_found


def get_stack_start_and_end(pid):
        f = open('/proc/' + str(pid) + '/maps', 'r')
        for line in f.readlines():
            if '[stack]' in line:
                addrs = line.split(' ')[0]
                addrs = addrs.split('-')
                start = int(addrs[0], 16)
                end = int(addrs[1], 16)
        return (start, end)


def cleanup_quotes(quo):
    if quo.startswith('"'):
        quo = quo[1:]
    if quo.endswith('"'):
        quo = quo[:-1]
    return quo
