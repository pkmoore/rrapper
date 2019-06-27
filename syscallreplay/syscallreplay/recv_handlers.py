from __future__ import print_function
import logging
import util


def recvmsg_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    recvmsg call entry handler that optionally replays based
    on fd. It does several things:
    1. Retrieve parameters of socketcall from ECX register
    2. Validate sockfd argument
    3. Determine replay based on file descriptor from trace
    TODO: implement features

    Checks:
    0: int sockfd: socket file descriptor

    Sets:
    return value
    errno

  <Returns>
    None

  """
  logging.debug('Entering recvmsg entry handler')
  p = util.cint.peek_register(pid, util.cint.ECX)
  params = util.extract_socketcall_parameters(pid, p, 1)
  util.validate_integer_argument(pid, syscall_object, 0, 0, params)
  fd_from_trace = int(syscall_object.args[0].value)
  if should_replay_based_on_fd(fd_from_trace):
    raise NotImplementedError('recvmsg entry handler not '
                              'implemented for tracked sockets')
  else:
    logging.debug('Not replaying this system call')
    swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)





def recvmsg_exit_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    recvmsg call exit handler.

  <Returns>
    None

  """
  # TODO: apply return conditions?
  pass





def recv_subcall_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    recv subcall entry handler that replays based on fd. It does several 
    things:
    1. Retrieve parameters of socketcall from ECX register 
    2. Validate sockfd and length arguments.
    3. Determine if replay is necessary by fd from trace
    If replay: 
      4. Noop the current system call
      5. Retrieve buffer pointer address and cleaned up
         data in the buffer
      6. Use buffer address and retrieved data to populate the buffer
      7. Sets the return value
    If not replayed:
      4. Swap trace fd to execution

  Checks:
  0: int sockfd
  2: size_t len

  Sets:
  1: void *buf: buffer representing data received
  return value
  errno

  <Returns>
    None
  """
  p = util.cint.peek_register(pid, util.cint.ECX)
  params = util.extract_socketcall_parameters(pid, p, 4) 
  # We don't check params[1] because it is the address of an empty buffer
  # We don't check params[3] because it is a flags field
  util.validate_integer_argument(pid, syscall_object, 0, 0, params)
  util.validate_integer_argument(pid, syscall_object, 2, 2, params)
  # Decide if we want to replay this system call
  fd_from_trace = syscall_object.args[0].value
  if should_replay_based_on_fd(fd_from_trace):
    logging.info('Replaying this system call')
    util.noop_current_syscall(pid)
    buffer_address = params[1]
    data = util.cleanup_quotes(syscall_object.args[1].value)
    data = data.decode('string_escape')
    util.cint.populate_char_buffer(pid,
                                   buffer_address,
                                   data)
    util.apply_return_conditions(pid, syscall_object)
  else:
    logging.info("Not replaying this system call")
    swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)





def recvfrom_subcall_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    recvfrom subcall entry handler that replays based on fd. It does
    several things:
    1. Retrieve parameters of socketcall from ECX register
    2. Validate sockfd and length argument
    3. Retrieve buffer address, length, and sockadrr struct address
    4. From sockaddr src_addr, retrieve attributes
    5. Determine if replay is necessary based on fd
    If replay:
      6. Noop out the current system call
      7. Raise error if length of data is not requal to return value
      8. Populate *buf argument of given length and data
      from retrieved values
      9. Populate the sockaddr *addr parameter.
      10. Check if data in buffer at trace and execution match
      11. Sets return value
    If not replay:
      6. Swap trace fd to execution

    Checks:
    0: int sockfd
    2: size_t len

    Sets:
    1: void *buf: buffer representing message being received
    4: struct sockaddr *src_addr: 
          attributes of sockaddr representing source address
    return value
    errno

  <Returns>
    None

  """
  p = util.cint.peek_register(pid, util.cint.ECX)
  params = util.extract_socketcall_parameters(pid, p, 6)
  util.validate_integer_argument(pid, syscall_object, 0, 0, params)
  util.validate_integer_argument(pid, syscall_object, 2, 2, params)
  # We don't check params[1] because it is the address of an empty buffer
  # We don't check params[3] because it is a flags field
  # We don't check params[4] because it is the address of an empty buffer
  # We don't check params[5] because it is the address of a length
  data_buf_addr_e = params[1]
  data_buf_length_e = params[2]
  sockaddr_addr_e = params[4]
  sockaddr_length_addr_e = params[5]

  fd_t = syscall_object.args[0].value
  data = syscall_object.args[1].value
  data = util.cleanup_quotes(data)
  data = data.decode('string_escape')
  sockfields = syscall_object.args[4].value
  port = int(sockfields[1].value)
  ip = sockfields[2].value
  sockaddr_length_t = int(syscall_object.args[5].value.strip('[]'))

  ret_val = int(syscall_object.ret[0])

  # Decide if we want to replay this system call
  if should_replay_based_on_fd(fd_t):
    logging.info('Replaying this system call')
    util.noop_current_syscall(pid)
    if len(data) != ret_val:
      raise util.ReplayDeltaError('Decoded bytes length ({}) does not equal '
                             'return value from trace ({})'
                             .format(len(data), ret_val))
    util.cint.populate_char_buffer(pid, data_buf_addr_e, data)
    util.cint.populate_af_inet_sockaddr(pid,
                                   sockaddr_addr_e,
                                   port,
                                   ip,
                                   sockaddr_length_addr_e,
                                   sockaddr_length_t)
    buf = util.cint.copy_address_range(pid,
                                  data_buf_addr_e,
                                  data_buf_addr_e + data_buf_length_e)
    if buf[:ret_val] != data:
      raise util.ReplayDeltaError('Data copied by read() handler doesn\'t '
                                  'match after copy')
    util.apply_return_conditions(pid, syscall_object)
    print(util.cint.peek_register(pid, util.cint.EAX))
  else:
    logging.info('Not replaying this system call')
    swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)
