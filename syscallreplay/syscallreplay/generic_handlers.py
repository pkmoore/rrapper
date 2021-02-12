"""
<Program Name>
  generic_handlers

<Purpose>
  Provide several generic system call handlers that can perform a common set of
  operations for any system call.  These calls are useful for dealing with
  simple system calls that do not require any specialized operations to handle
  correctly.

"""


import logging

import errno_dict
import util

import syscallreplay

def syscall_return_success_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    Generic handler that does two things:
    1. Noop out the current system call
    2. Sets the return value from the current syscall_object
    Checks:
    Nothing

    Sets:
    return value: The return value specified in syscall_object
        (added as replay file descriptor)
    errno
  <Returns>
    None

  """
  logging.debug('Using default "return success" handler')
  util.noop_current_syscall(pid)
  util.apply_return_conditions(pid, syscall_object)





def check_return_value_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    Generic handler that works in concert with
    check_return_value_exit_handler to check whether the return value from
    allowing a system call to pass through matches the system call recorded
    for the same system call in syscall_object.
    Checks:
    Nothing

    Sets:
    Nothing
  <Returns>
    None

  """
  logging.debug('check_return_value entry handler')
  logging.debug('Letting system call %d : %s pass through',
                syscall_id,
                syscall_object.name)





def check_return_value_exit_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    Generic handler that works with
    check_return_value_entry_handler to check whether the return value from
    allowing a system call to pass through matches the system call recorded
    for the same system call in syscall_object.  This is where the actual
    checking happens
    Checks:
    The return value from syscall execution

    Sets:
    Nothing
  <Returns>
    None

  """
  logging.debug('check_return_value exit handler')
  ret_from_execution = syscallreplay.peek_register(pid, syscallreplay.EAX)
  ret_from_trace = util.cleanup_return_value(syscall_object.ret[0])
  logging.debug('Return value from execution %x', ret_from_execution)
  logging.debug('Return value from trace %x', ret_from_trace)
  # HACK HACK HACK
  if syscall_object.ret[1] is not None:
    logging.debug('We have an errno code')
    logging.debug('Errno code: %s', syscall_object.ret[1])
    errno_retval = -1 * errno_dict.ERRNO_CODES[syscall_object.ret[1]]
    logging.debug('Errno ret_val: %d', errno_retval)
    if errno_retval == ret_from_execution:
      return
  if ret_from_execution < 0:
    ret_from_execution &= 0xffffffff
  if ret_from_execution != ret_from_trace:
    raise util.ReplayDeltaError('Return value from execution ({}, {:02x}) '
      'differs from return value from trace '
      '({}, {:02x})'
      .format(ret_from_execution,
        ret_from_execution,
        ret_from_trace,
        ret_from_trace))
