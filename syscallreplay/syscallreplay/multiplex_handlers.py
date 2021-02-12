from __future__ import print_function
import logging
import re

from util import *
from poll_parser import (
    parse_poll_results,
    parse_poll_input,
)


def select_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering select entry handler')
    while syscall_object.ret[0] == '?':
        logging.debug('Got interrupted select. Will advance past')
        syscall_object = advance_trace()
        logging.debug('Got new line %s', syscall_object.original_line)
        if syscall_object.name != 'select':
            raise Exception('Attempt to advance past interrupted accept line '
                            'failed. Next system call was not accept!')
    noop_current_syscall(pid)
    timeval_addr = None
    seconds = 0
    microseconds = 0
    if syscall_object.args[4].value != 'NULL':
        timeval_addr = cint.peek_register_unsigned(pid, cint.EDI)
        logging.debug('timeval_addr: %x', timeval_addr)
        logging.debug('seconds: %d', seconds)
        logging.debug('microseconds: %d', microseconds)
    readfds_addr = cint.peek_register_unsigned(pid, cint.ECX)
    logging.debug('readfds addr: %x', readfds_addr)
    writefds_addr = cint.peek_register_unsigned(pid, cint.EDX)
    logging.debug('writefds addr: %x', writefds_addr)
    exceptfds_addr = cint.peek_register_unsigned(pid, cint.ESI)
    logging.debug('exceptfds addr: %x', exceptfds_addr)
    readfds = []
    writefds = []
    exceptfds = []
    if int(syscall_object.ret[0]) != 0:
        ol = syscall_object.original_line
        ret_line = ol.split('=')[1]
        ret_line = ret_line.split('(')[1].strip(')')
        in_substr = re.search(r'in \[(\d\s?)*\]', ret_line)
        if in_substr:
            in_substr = in_substr.group(0)
            in_fds = in_substr.split(' ')[1:]
            readfds = [int(x.strip('[]')) for x in in_fds]
        out_substr = re.search(r'out \[(\d\s?)*\]', ret_line)
        if out_substr:
            out_substr = out_substr.group(0)
            out_fds = out_substr.split(' ')[1:]
            writefds = [int(x.strip('[]')) for x in out_fds]
        if 'exc' in ret_line:
            raise NotImplementedError('outfds and exceptfds not supported')
        left_substr = re.search(r'left \{[0-9]*, [0-9]*\}$', ret_line)
        if left_substr and timeval_addr != 0:
            left_substr = ol[ol.rfind('left'):]
            left_substr = left_substr.split('{')[1]
            seconds = int(left_substr.split(',')[0])
            microseconds = int(left_substr.split(',')[1].strip(' ').rstrip('})'))
    else:
        logging.debug('Select call timed out')
    logging.debug('Populating bitmaps')
    logging.debug('readfds: %s', readfds)
    logging.debug('writefds: %s', writefds)
    logging.debug('exceptfds: %s', exceptfds)
    cint.populate_select_bitmaps(pid,
                                 readfds_addr,
                                 readfds,
                                 writefds_addr,
                                 writefds,
                                 exceptfds_addr,
                                 exceptfds)
    if timeval_addr:
        logging.debug('Populating timeval structure')
        cint.populate_timeval_structure(pid,
                                        timeval_addr,
                                        seconds,
                                        microseconds)
    apply_return_conditions(pid, syscall_object)


def poll_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    nothing
    Sets:
    return value: Number of struct with non-zero revents or -1 (error)
    errno

    Not Implemented:
    * Determine what is not implemented
    """
    logging.debug('Entering poll entry handler')
    array_address = cint.peek_register(pid, cint.EBX)
    if syscall_object.ret[0] == 0:
        logging.debug('Poll call timed out')
    else:
        in_pollfds = parse_poll_input(syscall_object)
        out_pollfds = parse_poll_results(syscall_object)
        logging.debug('Input pollfds: %s', in_pollfds)
        logging.debug('Returned event: %s', out_pollfds)
        logging.debug('Pollfd array address: %s', array_address)
        logging.debug('Child PID: %s', pid)
        index = 0
        for i in in_pollfds:
            array_address = array_address + (index * cint.POLLFDSIZE)
            found = False
            for o in out_pollfds:
                if i['fd'] == o['fd']:
                    cint.write_poll_result(pid,
                                           array_address,
                                           o['fd'],
                                           o['revents'])
                    found = True

            if not found:
                # For applications that re-use the pollfd array, we must clear
                # the revents field in case they don't do it themselves.
                cint.write_poll_result(pid,
                                       array_address,
                                       i['fd'],
                                       0)
            index += 1
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def epoll_create_entry_handler(sycall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: integer flags
    Sets:
    return value: The file descriptor or -1 (error)
    errno

    Not Implemented:
    """
    logging.debug('Entering epoll_create entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    fd_from_trace = int(syscall_object.ret[0])
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def epoll_ctl_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: epfd: epoll instance file descriptor
    2: fd: file descriptor associated with the operation
    Sets:
    return value: success (0) or error (-1)
    errno

    Not Implemented:
    * Make sure there aren't any side-effects that need to be reproduced
    * Convert op to int and check it
    """
    logging.debug('Entering epoll_ctl entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    validate_integer_argument(pid, syscall_object, 2, 2)
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def epoll_wait_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    0: epfd: epoll instance file descriptor
    2: maxevents: number of events that can be returned
    3: timeout: how long to wait before returning with no results
    Sets:
    return value: Number of file desciptors with events or -1 (failure)
    errno

    Not Implemented:
    """

    logging.debug('Entering epoll_wait entry_handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    validate_integer_argument(pid, syscall_object, -2, 2)
    validate_integer_argument(pid, syscall_object, -1, 3)
    struct_str = syscall_object.original_line
    struct_str = struct_str[struct_str.find(',')+1:]
    struct_str = struct_str[:struct_str.rfind(',')]
    struct_str = struct_str[:struct_str.rfind(',')]
    struct_str = struct_str.strip(' []')
    events = []
    while struct_str != '':
        # ends in }}
        closing_curl_index = struct_str.find('}') + 1
        event = struct_str[1:struct_str.find(',')]
        if '|' in event:
            raise NotImplementError('multiple events unsupported')
        data_struct_start = struct_str[1:].find('{') + 1
        data_struct_end = closing_curl_index
        data_struct = struct_str[data_struct_start:data_struct_end]
        tmp = {}
        tmp['event'] = event
        data_dict = {}
        for i in data_struct.split(','):
            i = i.strip(' {}')
            data_dict[i.split('=')[0]] = i.split('=')[1]
        tmp['data'] = data_dict
        events.append(tmp)
        struct_str = struct_str[closing_curl_index+1:]
    try:
        for i in events:
            if int(i['data']['u32']) != 0xFFFFFFFF & int(i['data']['u64']):
                raise NotImplementError('differing u32 and u64 unsupported')
    except KeyError:
        raise NotImplementedError('both u32 and u64 required')

    addr = cint.peek_register(pid, cint.ECX)
    logging.debug('addr: %x', addr)
    noop_current_syscall(pid)
    for i in events:
        cint.write_epoll_struct(pid,
                                addr,
                                EPOLL_EVENT_TO_NUM[i['event']],
                                int(i['data']['u64']))
        # sizeof(struct epoll_event)
        addr += 12
    apply_return_conditions(pid, syscall_object)


def select_entry_debug_printer(pid, orig_eax, syscall_object):
    readfds_addr = cint.peek_register(pid, cint.ECX)
    writefds_addr = cint.peek_register(pid, cint.EDX)
    exceptfds_addr = cint.peek_register(pid, cint.EDI)
    logging.debug("nfds: %d", cint.peek_register(pid, cint.EBX))
    logging.debug("readfds_addr: %x", readfds_addr & 0xffffffff)
    logging.debug("writefds_addr: %x", writefds_addr & 0xffffffff)
    logging.debug("exceptfds_addr: %x", exceptfds_addr & 0xffffffff)
    if readfds_addr != 0:
        logging.debug("readfds: %s",
                      cint.get_select_fds(pid, readfds_addr))
    if writefds_addr != 0:
        logging.debug("writefds: %s",
                      cint.get_select_fds(pid, writefds_addr))
    if exceptfds_addr != 0:
        logging.debug("exceptfds_addr: %s",
                      cint.get_select_fds(pid, exceptfds_addr))
