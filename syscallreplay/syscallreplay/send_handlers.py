"""
<Program Name>
  send_handlers

<Purpose>
  Provide system call handlers for send variants,
  which provide data transfering mechanisms.

"""

import logging
import util


def sendfile_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    sendfile call entry handler that always replays.
    It does several things:
    1. Validate the out and in fds, and the byte count
    2. Noop out the current system call
    3. Check offset argument
    4. If offset is NULL, check
    5. Set return value

    Checks:
    0: int out_fd - file descriptor for reading
    1: int in_fd - file descriptor writing
    3: size_t count - bytes written

    Sets:
    return value
    errno

  <Returns>
    None
  
  """
  logging.debug('Entering sendfile entry handler')
  
  # validate file descriptors and count arg
  util.validate_integer_argument(pid, syscall_object, 0, 0)
  util.validate_integer_argument(pid, syscall_object, 1, 1)
  util.validate_integer_argument(pid, syscall_object, 3, 3)
  offset = syscall_object.args[2].value
  util.noop_current_syscall(pid)
  if offset != 'NULL':
    offset_addr = util.cint.peek_register_unsigned(pid, util.cint.EDX)
    util.cint.populate_int(pid, offset_addr, int(offset))
  util.apply_return_conditions(pid, syscall_object)





def send_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    Send call entry handler that always replays. It does several 
    things:
    1. Peek ECX register for system call parametrs
    2. Validate sockfd and message length
    3. Noop out the current syscall
    4. Set return value

    Checks:
    0: int sockfd: file descriptor or sending socket
    2: size_t len: length of const void *buf

    Sets:

  <Returns>
    None

  """
  logging.debug('Entering send entry handler')
  ecx = util.cint.peek_register(pid, util.cint.ECX)
  params = util.extract_socketcall_parameters(pid, ecx, 3)
  util.validate_integer_argument(pid, syscall_object, 0, 0, params=params)
  util.validate_integer_argument(pid, syscall_object, 2, 2, params=params)
  trace_fd = int(syscall_object.args[0].value)
  # TODO: compare trace fd against execution fd????
  util.noop_current_syscall(pid)
  util.apply_return_conditions(pid, syscall_object)





def send_exit_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    send call exit handler that always replays. It checks the
    return value from trace and execution.
  
  <Returns>
    None

  """
  logging.debug('Entering send exit handler')
  ret_val_from_trace = syscall_object.ret[0]
  ret_val_from_execution = util.cint.peek_register(pid, util.cint.EAX)
  if ret_val_from_execution != ret_val_from_trace:
    raise ReplayDeltaError('Return value from execution ({}) differs '
                           'from return value from trace ({})'
                           .format(ret_val_from_execution,
                                   ret_val_from_trace))





def sendto_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    sendto call entry handler that replays based on fd from trace.
    It does several things:
    1. Peek ECX for system call parameters
    2. Validate sockfd and message length
    3. Check if replay is necessary based on fd from trace

    Checks:
    0: int sockfd 
    2: size_t len

  <Returns>
    None
  """
  logging.debug('Entering sendto entry handler')
  p = util.cint.peek_register(pid, util.cint.ECX)
  params = util.extract_socketcall_parameters(pid, p, 3)
  fd_from_trace = int(syscall_object.args[0].value)
  util.validate_integer_argument(pid, syscall_object, 0, 0, params=params)
  util.validate_integer_argument(pid, syscall_object, 2, 2, params=params)
  if should_replay_based_on_fd(fd_from_trace):
    logging.debug('Replaying this system call')
    subcall_return_success_handler(syscall_id, syscall_object, pid)
  else:
    logging.debug('Not replaying this call')
    swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)





def sendto_exit_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    sendto call exit handler. Does nothing at the moment.

  <Returns>
    None
  """
  pass





def sendmmsg_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    sendmmsg call entry handler that replays based on trace sockfd.
    It does several things:
    1. Validate sockfd
    2. Determine replay based on trace sockfd
    3. Noop out the current system call if replay is necessary
    4. Check return value to be successful when replaying, and retrieve
    messages
    5. Extract socketcall parameters, and retrieve address
    6. TODO

    Checks:
    0: int sockfd: file descriptor of transmitting file descriptor

    Sets:
    return value
    errno

  <Returns>
    None
  
  """
  logging.debug('Entering sendmmsg entry handler')
  sockfd_from_trace = syscall_object.args[0].value
  util.validate_integer_argument(pid, syscall_object, 0, 0)
  if should_replay_based_on_fd(sockfd_from_trace):
    logging.debug('Replaying this sytem call')
    util.noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
      logging.debug('Got successful sendmmsg call')
      number_of_messages = syscall_object.ret[0]
      if syscall_id == 102:
        p = util.cint.peek_register(pid, util.cint.ECX)
        params = util.extract_socketcall_parameters(pid, p, 4)
        addr = params[1]
      else:
        addr = util.cint.peek_register(pid, util.cint.ECX)
      logging.debug('Number of messages %d', number_of_messages)
      logging.debug('Address of buffer %x', addr & 0xffffffff)
      lengths = [int(syscall_object.args[x].value.rstrip('}'))
                 for x in range(6, (number_of_messages * 6) + 1, 6)]
      logging.debug('Lengths: %s', lengths)
      util.cint.write_sendmmsg_lengths(pid, addr, number_of_messages, lengths)
    else:
      logging.debug('Got unsuccessful sendmmsg call')
    util.apply_return_conditions(pid, syscall_object)
  else:
    logging.debug('Not replaying this system call')
    swap_trace_fd_to_execution_fd(pid, 0, syscall_object)





def sendmmsg_exit_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    sendmmsg call exit handler. This is a placeholder

  <Returns>
    None
  
  """

  # TODO: determine what needs to be implemented here
  logging.debug('Entering sendmmsg exit handler')
  pass
