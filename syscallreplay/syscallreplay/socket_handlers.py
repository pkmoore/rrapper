from os_dict import ADDRFAM_INT_TO_FAM
from os_dict import PROTOFAM_INT_TO_FAM
from os_dict import SHUTDOWN_INT_TO_CMD
from os_dict import SOCKTYPE_INT_TO_TYPE

from util import (extract_socketcall_parameters,
                  ReplayDeltaError,
                  logging,
                  cint,
                  noop_current_syscall,
                  apply_return_conditions,
                  validate_integer_argument,
                  subcall_return_success_handler,)

def bind_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering bind entry handler')
    p = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, p, 1)
    fd_from_trace = int(syscall_object.args[0].value)
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    logging.debug('Replaying this system call')
    subcall_return_success_handler(syscall_id, syscall_object, pid)


def bind_exit_handler(syscall_id, syscall_object, pid):
    pass


def listen_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering listen entry handler')
    p = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, p, 1)
    fd_from_trace = int(syscall_object.args[0].value)
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    logging.debug('Replaying this system call')
    subcall_return_success_handler(syscall_id, syscall_object, pid)


def listen_exit_handler(syscall_id, syscall_object, pid):
    pass


def getpeername_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getpeername handler')
    # Pull out the info that we can check
    ecx = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    fd = params[0]
    # We don't compare params[1] because it is the address of an empty buffer
    # We don't compare params[2] because it is the address of an out parameter
    # Get values from trace for comparison
    fd_from_trace = syscall_object.args[0].value
    # Check to make sure everything is the same
    if fd != int(fd_from_trace):
        raise ReplayDeltaError('File descriptor from execution ({}) '
                               'does not match file descriptor from trace ({})'
                               .format(fd, fd_from_trace))
    # Decide if this is a file descriptor we want to deal with
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        logging.debug('Got successful getpeername call')
        addr = params[1]
        length_addr = params[2]
        length = int(syscall_object.args[2].value.strip('[]'))
        logging.debug('Addr: %d', addr)
        logging.debug('Length addr: %d', length_addr)
        logging.debug('Length: %d', length)
        sockfields = syscall_object.args[1].value
        family = sockfields[0].value
        port = int(sockfields[1].value)
        ip = sockfields[2].value
        logging.debug('Family: %s', family)
        logging.debug('Port: %d', port)
        logging.debug('Ip: %s', ip)
        if family != 'AF_INET':
            raise NotImplementedError('getpeername only '
                                          'supports AF_INET')
        cint.populate_af_inet_sockaddr(pid,
                                              addr,
                                              port,
                                              ip,
                                              length_addr,
                                              length)
    else:
        logging.debug('Got unsuccessful getpeername call')
    apply_return_conditions(pid, syscall_object)


def getsockname_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: The socket file descriptor
    Sets:
    addr: a struct sockaddr populated with the requested information
    addrlen: length of the sockaddr struct being populated
    return value: 0 (success) or -1 (failure)
    errno

    Not Implemented:
    * Use address validator to check the addresses
    """
    logging.debug('Entering getsockname handler')
    # Pull out the info that we can check
    ecx = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    # We don't compare params[1] because it is the address of an empty buffer
    # We don't compare params[2] because it is the address of an out parameter
    # Get values from trace for comparison
    fd_from_trace = syscall_object.args[0].value
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # Decide if this is a file descriptor we want to deal with
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        logging.debug('Got successful getsockname call')
        addr = params[1]
        length_addr = params[2]
        length = int(syscall_object.args[2].value.strip('[]'))
        logging.debug('Addr: %d', addr & 0xffffffff)
        logging.debug('Length addr: %d', length_addr & 0xffffffff)
        logging.debug('Length: %d', length)
        sockfields = syscall_object.args[1].value
        family = sockfields[0].value
        port = int(sockfields[1].value)
        ip = sockfields[2].value
        logging.debug('Family: %s', family)
        logging.debug('Port: %d', port)
        logging.debug('Ip: %s', ip)
        if family != 'AF_INET':
            raise NotImplementedError('getsockname only supports '
                                          'AF_INET')
        cint.populate_af_inet_sockaddr(pid,
                                       addr,
                                       port,
                                       ip,
                                       length_addr,
                                       length)
    else:
        logging.debug('Got unsuccessful getsockname call')
    apply_return_conditions(pid, syscall_object)


def getsockname_exit_handler(syscall_id, syscall_object, pid):
    pass


def shutdown_subcall_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: sockfd: the socket file descriptor
    Sets:
    return value: 0 (success) or -1 (error)
    errno

    """
    logging.debug('Entering shutdown entry handler')
    # Pull out the info we can check
    ecx = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, ecx, 2)
    fd_from_trace = syscall_object.args[0].value
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # TODO: We need to check the 'how' parameter here
    # Check to make sure everything is the same
    # Decide if we want to replay this system call
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def setsockopt_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: sockfd: the socket file descriptor
    Sets:
    optval: out parameter
    return value: 0 (success) or -1 (error)
    errno

    Not Implemented: More checking

    """
    logging.debug('Entering setsockopt handler')
    ecx = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, ecx, 5)
    fd_from_trace = int(syscall_object.args[0].value)
    optval_addr = params[3]
    # We don't check param[3] because it is an address of an empty buffer
    # We don't check param[4] because it is an address of an empty length
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def getsockopt_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: The socket file descriptor
    Sets:
    optval: The value being retrieved
    optval_len: The length of the value being retrieved
    return value: 0 (success) or 1 (failure)
    errno

    Not Implemented:
    * Use the address validator to check addresses
    """
    logging.debug('Entering getsockopt handler')
    # Pull out what we can compare
    ecx = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, ecx, 5)
    fd_from_trace = int(syscall_object.args[0].value)
    optval_addr = params[3]
    optval_len_addr = params[4]
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # This if is sufficient for now for the implemented options
    if params[1] != 1 or params[2] != 4:
        raise NotImplementedError('Unimplemented getsockopt level or optname')
    optval_len = int(syscall_object.args[4].value.strip('[]'))
    if optval_len != 4:
        raise NotImplementedError('getsockopt() not implemented for '
                                      'optval sizes other than 4')
    optval = int(syscall_object.args[3].value.strip('[]'))
    logging.debug('Optval: %s', optval)
    logging.debug('Optval Length: %s', optval_len)
    logging.debug('Optval addr: %x', optval_addr & 0xffffffff)
    logging.debug('Optval Lenght addr: %d', optval_len_addr & 0xffffffff)
    noop_current_syscall(pid)
    cint.populate_int(pid, optval_addr, optval)
    cint.populate_int(pid, optval_len_addr, 4)
    apply_return_conditions(pid, syscall_object)


def connect_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: The socket file descriptor
    2: The length of the sockaddr structure pointed to by 1
    Sets:
    return value: file descriptor of the new socket -1 (error)
    errno

    Not Implemented:
    * Determine what is not implemented
    """

    logging.debug('Entering connect entry handler')
    ecx = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    validate_integer_argument(pid, syscall_object, 2, 2, params=params)
    trace_fd = int(syscall_object.args[0].value)
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def connect_exit_handler(syscall_id, syscall_object, pid):
    ret_val_from_trace = syscall_object.ret[0]
    ret_val_from_execution = cint.peek_register(pid, cint.EAX)
    if ret_val_from_execution != ret_val_from_trace:
        raise ReplayDeltaError('Return value from execution ({}) differs '
                               'from return value from trace ({})'
                               .format(ret_val_from_execution,
                                       ret_val_from_trace))


def socket_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering socket exit handler')
    fd_from_execution = cint.peek_register(pid, cint.EAX)
    fd_from_trace = int(syscall_object.ret[0])
    if offset_file_descriptor(fd_from_trace) != fd_from_execution:
        raise ReplayDeltaError('File descriptor from execution ({}) '
                               'differs from file descriptor from '
                               'trace ({})'
                               .format(fd_from_execution, fd_from_trace))
    if fd_from_execution >= 0:
        add_os_fd_mapping(fd_from_execution, fd_from_trace)
    cint.poke_register(pid, cint.EAX, fd_from_trace)


# TODO: There is a lot more checking to be done here
def socket_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: The domain of the socket
    Sets:
    return value: file descriptor of the new socket -1 (error)
        (added as replay file descriptor)
    errno

    Not Implemented:
    * Determine what is not implemented
    """
    logging.debug('Entering socket subcall entry handler')

    ecx = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    # Only PF_INET and PF_LOCAL socket calls are handled
    execution_is_PF_INET = (params[0] == cint.PF_INET)
    trace_is_PF_INET = (str(syscall_object.args[0]) == '[\'PF_INET\']')
    execution_is_PF_LOCAL = (params[0] == 1)  # define PF_LOCAL 1
    trace_is_PF_LOCAL = (str(syscall_object.args[0]) == '[\'PF_LOCAL\']')
    logging.debug('Execution is PF_INET: %s', execution_is_PF_INET)
    logging.debug('Trace is PF_INET: %s', trace_is_PF_INET)
    logging.debug('Exeuction is PF_LOCAL: %s', execution_is_PF_LOCAL)
    logging.debug('Trace is PF_LOCAL: %s', trace_is_PF_LOCAL)
    if execution_is_PF_INET != trace_is_PF_INET:
        raise ReplayDeltaError('Encountered socket subcall with mismatch between '
                        'execution protocol family and trace protocol family')
    if execution_is_PF_LOCAL != trace_is_PF_LOCAL:
        raise ReplayDeltaError('Encountered socket subcall with mismatch between '
                        'execution protocol family and trace protocol family')
    # Decide if we want to deal with this socket call or not
    if trace_is_PF_INET or \
       execution_is_PF_INET or \
       trace_is_PF_LOCAL or \
       execution_is_PF_LOCAL:
        noop_current_syscall(pid)
        fd = int(syscall_object.ret[0])
        logging.debug('File Descriptor from trace: %s', fd)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Ignoring non-PF_INET call to socket')


def accept_subcall_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: sockfd: the socket file descriptor
    Sets:
    return value: The file descriptor -1 (error)
    errno

    Not Implemented:
    * Implement a function to check null terminated strings to clean up this
      mess of checking
    """
    logging.debug('Checking if line from trace is interrupted accept')
    if syscall_object.ret[0] == '?':
        raise NotImplementedError('Interrupted accept()s not implemented')
    ecx = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    sockaddr_addr = params[1]
    sockaddr_len_addr = params[2]
    fd_from_trace = syscall_object.args[0].value
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # Decide if this is a system call we want to replay
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1 and syscall_object.args[1].value != 'NULL':
        sockfields = syscall_object.args[1].value
        family = sockfields[0].value
        port = int(sockfields[1].value)
        ip = sockfields[2].value
        sockaddr_length = int(syscall_object.args[2].value.strip('[]'))
        logging.debug('Family: %s', family)
        logging.debug('Port: %s', port)
        logging.debug('IP: %s', ip)
        logging.debug('sockaddr Length: %s', sockaddr_length)
        logging.debug('sockaddr addr: %x', sockaddr_addr & 0xffffffff)
        logging.debug('sockaddr length addr: %x',
                      sockaddr_len_addr & 0xffffffff)
        logging.debug('pid: %s', pid)
        cint.populate_af_inet_sockaddr(pid,
                                              sockaddr_addr,
                                              port,
                                              ip,
                                              sockaddr_len_addr,
                                              sockaddr_length)
    if syscall_object.ret[0] != -1:
        ret = syscall_object.ret[0]
    apply_return_conditions(pid, syscall_object)


def accept_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering accept exit handler')
    fd_from_execution = cint.peek_register(pid, cint.EAX)
    fd_from_trace = int(syscall_object.ret[0])
    if offset_file_descriptor(fd_from_trace) != fd_from_execution:
        raise ReplayDeltaError('File descriptor from execution ({}) '
                               'differs from file descriptor from '
                               'trace ({})'
                               .format(fd_from_execution, fd_from_trace))
    if fd_from_execution >= 0:
        add_os_fd_mapping(fd_from_execution, fd_from_trace)
    cint.poke_register(pid, cint.EAX, fd_from_trace)


def socketcall_debug_printer(pid, orig_eax, syscall_object):
    subcall_debug_printers = {
        1: socket_debug_printer,
        9: send_debug_printer,
        13: shutdown_debug_printer
    }
    subcall_id = cint.peek_register(pid, cint.EBX)
    logging.debug('Got subcall {} {}'.format(subcall_id,
                                             SOCKET_SUBCALLS[subcall_id]))
    try:
        subcall_debug_printers[subcall_id](pid, syscall_object)
    except KeyError as e:
        logging.warning('This subcall ({}) has no debug printer'
                        .format(subcall_id))
        raise e


def send_debug_printer(pid, syscall_object):
    p = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, p, 4)
    addr = params[1]
    size = params[2]
    data = cint.copy_address_range(pid, addr, addr + size)
    logging.debug('This call tried to send: %s', data.encode('string-escape'))


def shutdown_debug_printer(pid, syscall_object):
    p = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, p, 2)
    fd = params[0]
    cmd = params[1]
    logging.debug('This call tried to shutdown: %d', fd)
    logging.debug('Command: %d: %s', cmd, SHUTDOWN_INT_TO_CMD[params[1]])


def socket_debug_printer(pid, syscall_object):
    p = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, p, 3)
    logging.debug('Domain: %s', ADDRFAM_INT_TO_FAM[params[0]])
    logging.debug('Type: %s', SOCKTYPE_INT_TO_TYPE[params[1]])
    logging.debug('Protocol: %s', PROTOFAM_INT_TO_FAM[params[2]])
