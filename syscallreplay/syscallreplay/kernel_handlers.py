from __future__ import print_function

import sys
import logging

from os_dict import IOCTLS_INT_TO_IOCTL
from os_dict import SIGNAL_INT_TO_SIG
from os_dict import SIGPROCMASK_INT_TO_CMD
from os_dict import STACK_SS_TO_INT
from os_dict import SIGNAL_SIG_TO_INT
from os_dict import SIGNAL_DFLT_HANDLER_TO_INT
from os_dict import SIGNAL_FLAG_TO_HEX

from util import (ReplayDeltaError,
                  logging,
                  cint,
                  noop_current_syscall,
                  apply_return_conditions,
                  cleanup_return_value,
                  validate_integer_argument,
                  validate_address_argument,
                  validate_return_value,
                  next_syscall,)

# Track whether the flags and prot of injected state brk() records are
# supported.  Store this result here once we have done this one time so we
# don't have to re-check for every brk() call
flags_and_prot_ok = False

def brk_entry_handler(syscall_id, syscall_object, pid):
    """Faked out creatively. Only check the integer argument
    Checks:
    0: void* addr: The address to which the program break should be set
    Sets:
    the return value: The new program break

    Special Action:
    Simulates brk() by crafting a mmap2() call that maps the same region of
    memory.

    TODO: Clean up printing and all that

    """

    logging.debug('brk entry handler')
    _check_flags_and_prot(cint.injected_state['brks'])
    validate_address_argument(pid,
                              syscall_object,
                              0,
                              0,
                              except_on_mismatch=False)
    last_map_start = cint.injected_state['brks'][-1]['start']
    last_map_size = cint.injected_state['brks'][-1]['size']
    # If flags are 0, we are shrinking, so the end of our last mapping is
    # actually the address, rather than address + size
    if cint.injected_state['brks'][-1]['flags'] == 0:
        last_map_end = last_map_start
    else:
        last_map_end = last_map_start + last_map_size

    new_brk = int(syscall_object.ret[0], 16)
    new_map_size = new_brk - last_map_end

    if new_brk < last_map_end:
        raise NotImplementedError('munmap required here! Not implemented!')

    logging.debug('Last map end: %x', last_map_end)
    logging.debug('New map size: %x', new_map_size)
    logging.debug('New map end: %x', last_map_end + new_map_size)

    # Preserve the registers mmap uses for parameters
    save_EBX  = cint.peek_register(pid, cint.EBX)
    save_ECX  = cint.peek_register(pid, cint.ECX)
    save_EDX  = cint.peek_register(pid, cint.EDX)
    save_ESI  = cint.peek_register(pid, cint.ESI)
    save_EDI  = cint.peek_register(pid, cint.EDI)
    save_EBP  = cint.peek_register(pid, cint.EBP)


    # transform current system call to mmap
    cint.poke_register(pid, cint.ORIG_EAX, 192)
    cint.poke_register(pid, cint.EAX, 192)
    # Where to start our new mapping from
    cint.poke_register(pid, cint.EBX, last_map_end)
    # How big of a mapping do we want
    cint.poke_register(pid, cint.ECX, new_map_size)
    # PROT options
    prot = 3 #cint.injected_state['brks'][-1]['prot']
    cint.poke_register(pid, cint.EDX, prot)
    # Flags options
    flags = 2 #cint.injected_state['brks'][-1]['flags']
    flags |= 32
    flags |= 16
    cint.poke_register(pid, cint.ESI, flags)
    # fd
    cint.poke_register(pid, cint.EDI, -1)
    # offset
    cint.poke_register(pid, cint.EBP, 0)

    # Advance to our crafted mmap's exit
    cint.syscall(pid, 0)
    next_syscall()

    # Record the new mapping we have put in place
    cint.injected_state['brks'].append({u'start': last_map_end,
                                        u'prot': 3,
                                        u'flags': 2,
                                        u'size': new_map_size})

   # restore registers
    cint.poke_register(pid, cint.EBX, save_EBX)
    cint.poke_register(pid, cint.ECX, save_ECX)
    cint.poke_register(pid, cint.EDX, save_EDX)
    cint.poke_register(pid, cint.ESI, save_ESI)
    cint.poke_register(pid, cint.EDI, save_EDI)
    cint.poke_register(pid, cint.EBP, save_EBP)

    apply_return_conditions(pid, syscall_object)
    cint.entering_syscall = False

def _check_flags_and_prot(brks):
    global flags_and_prot_ok
    if not flags_and_prot_ok:
        for i in brks:
            if i['flags'] != 0:
                if i['flags'] != 2:
                    raise NotImplementedError('Got unsupported flags value {} '
                                              'for {}'.format(i['flags'], i))
                if i['prot'] != 3:
                    raise NotImplementedError('Got unsupported prot value {} '
                                              'for {}'.format(i['prot'], i))
        flags_and_prot_ok = True

def _brk_debug_print_regs(pid):
    print('ORIG_EAX: ', cint.peek_register(pid, cint.ORIG_EAX))
    print('EAX: ', cint.peek_register(pid, cint.EAX))
    print('EBX: ', cint.peek_register(pid, cint.EBX))
    print('ECX: ', cint.peek_register(pid, cint.ECX))
    print('EDX: ', cint.peek_register(pid, cint.EDX))
    print('ESI: ', cint.peek_register(pid, cint.ESI))
    print('EDI: ', cint.peek_register(pid, cint.EDI))
    print('EBP: ', cint.peek_register(pid, cint.EBP))

def brk_exit_handler(syscall_id, syscall_object, pid):
    """Never Replay.  Only check the return value and WARN if it is
    different.  BASED ON THE ASSUMPTION THAT THE PROGRAM BREAK NOT MATCHING UP
    IS FINE TO IGNORE.
    Checks:
    return value: 0 (success) or -1 (failure)
    errno
    Sets:
    Nothing

    """

    logging.debug('brk exit handler')
    validate_return_value(pid, syscall_object, except_on_mismatch=False)


def rt_sigaction_entry_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering rt_sigaction entry handler")

    # check if there is an old action. as only need to worry about those
    old_action_found = syscall_object.args[-2].value.strip() != 'NULL'
    if not old_action_found:
        logging.debug("No rt_sigaction read intercepted!")
        noop_current_syscall(pid)
    else:
        logging.debug("rt_sigaction read intercepted")

        # figure out if there is a new action, and whether strace is showing the sa_restorer value in the actions
        restorer_value_in_trace = True
        new_action_found = syscall_object.args[1].value != "NULL"
        if (new_action_found):
            logging.debug("rt_sigaction write intercepted")
            restorer_value_in_trace = syscall_object.args[4].value.find('}') != -1
        else:
            restorer_value_in_trace = syscall_object.args[5].value.find('}') != -1

        logging.debug("Trace %s restorer values" % ('contains'
                                                    if restorer_value_in_trace
                                                    else 'does not contain'))

        # figure out at what indexes the old_action arguments will start and end at    
        if new_action_found and restorer_value_in_trace:
            old_action_start_pos = 5
        elif new_action_found:
            old_action_start_pos = 4
        else:
            old_action_start_pos = 2

        old_action_end_pos = old_action_start_pos + (4 if restorer_value_in_trace
                                                      else 3)

        # seperate out the old_action part of the trace    
        old_action_args = syscall_object.args[old_action_start_pos:old_action_end_pos]

        logging.debug("ARGUMENTS BEGIN")

        # these are the values we need to put into memory
        old_action_addr = 0
        old_sa_flags = 0
        old_sa_handler = 0
        old_sa_mask_list = []
        old_sa_restorer = 0
        # old_sa_sigaction = 0   # void (int, siginfo_t*, void*) Serves as an alternate for old_sa_handler but yet to be seen or implemented

        # buffer address
        old_action_addr = cint.peek_register(pid, cint.EDX)
        logging.debug("Old Action Address: 0x%x" % (old_action_addr & 0xffffffff))

        # done with registers so can noop now
        noop_current_syscall(pid)

        # now parse arguments out of the strace object
        # old_sa_flags
        old_flags_str = old_action_args[2].value.strip('{}')
        if (old_flags_str != '0'):
            old_flags_list = old_flags_str.split('|')
            logging.debug("FLAGS: " + str(old_flags_list))
            for flag in old_flags_list:
                flag_int = int(SIGNAL_FLAG_TO_HEX.get(flag))
                if (flag_int == None):
                    raise LookupError("The flag " + str(flag) + "  was not found")
                old_sa_flags += flag_int

        logging.debug("Old Flags: " + str(old_sa_flags))


        # if flags include SA_SIGINFO should use old_sa_sigaction instead of old_sa_handler
        should_use_sigaction = (old_sa_flags & 4) == 4
        if (should_use_sigaction):
            raise NotImplementedError("rt_sigaction should use sa_sigaction instead of sa_handler here but this functionality is not yet implemented")


        # old_sa_handler
        old_sa_handler_str = old_action_args[0].value.strip('{')
        logging.debug("Handler Raw: " + str(old_sa_handler_str));

        # handler is either one of 3 default handlers (in which case strace gives a name) or a pointer value
        default_handler_int = SIGNAL_DFLT_HANDLER_TO_INT.get(old_sa_handler_str)
        if (default_handler_int != None):
            old_sa_handler = default_handler_int
        else:
            old_sa_handler = int(old_sa_handler_str, 16)
        logging.debug("Old Handler: 0x%x" % (old_sa_handler & 0xffffffff))


        # sa_mask
        old_mask_list_str = old_action_args[1].value
        is_non_empty_list = old_mask_list_str != '[]'
        if (is_non_empty_list):
            old_mask_list = old_mask_list_str[1:-1].split(' ')

            # add 'SIG' to say 'PIPE' to make 'SIGPIPE' as strace leaves the beginning off
            old_mask_list = ["SIG" + name for name in old_mask_list if not str(name)[0:3] == "SIG"]
            # convert names into ints
            old_sa_mask_list = [SIGNAL_SIG_TO_INT[sig] for sig in old_mask_list]

        logging.debug("Old Mask List: " + str(old_sa_mask_list))


        # sa_restorer
        if restorer_value_in_trace:
            restorer_str = old_action_args[3].value.strip('}')
            old_sa_restorer = int(restorer_str, 16)
            logging.debug("Restorer: 0x%x " % (old_sa_restorer & 0xffffffff))
        else:
            logging.debug("No restorer found")

        logging.debug("ARGUMENTS END")

        cint.populate_rt_sigaction_struct(pid,
                                          old_action_addr,
                                          old_sa_handler,
                                          old_sa_mask_list,
                                          old_sa_flags,
                                          old_sa_restorer
        )

    # finish 
    apply_return_conditions(pid, syscall_object)


def getresuid_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getresuid entry handler')
    ruid = int(syscall_object.args[0].value.strip('[]'))
    euid = int(syscall_object.args[0].value.strip('[]'))
    suid = int(syscall_object.args[0].value.strip('[]'))
    ruid_addr = cint.peek_register(pid, cint.EBX)
    euid_addr = cint.peek_register(pid, cint.ECX)
    suid_addr = cint.peek_register(pid, cint.EDX)

    logging.debug('ruid: %d', ruid)
    logging.debug('euid: %d', euid)
    logging.debug('suid: %d', suid)

    logging.debug('ruid addr: %x', ruid_addr & 0xffffffff)
    logging.debug('ruid addr: %x', euid_addr & 0xffffffff)
    logging.debug('ruid addr: %x', suid_addr & 0xffffffff)
    noop_current_syscall(pid)

    cint.populate_unsigned_int(pid, ruid_addr, ruid)
    cint.populate_unsigned_int(pid, euid_addr, euid)
    cint.populate_unsigned_int(pid, suid_addr, suid)
    apply_return_conditions(pid, syscall_object)


def getresgid_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getresgid entry handler')
    ruid = int(syscall_object.args[0].value.strip('[]'))
    euid = int(syscall_object.args[0].value.strip('[]'))
    suid = int(syscall_object.args[0].value.strip('[]'))
    ruid_addr = cint.peek_register(pid, cint.EBX)
    euid_addr = cint.peek_register(pid, cint.ECX)
    suid_addr = cint.peek_register(pid, cint.EDX)

    logging.debug('ruid: %d', ruid)
    logging.debug('euid: %d', euid)
    logging.debug('suid: %d', suid)

    logging.debug('ruid addr: %x', ruid_addr & 0xffffffff)
    logging.debug('ruid addr: %x', euid_addr & 0xffffffff)
    logging.debug('ruid addr: %x', suid_addr & 0xffffffff)
    noop_current_syscall(pid)

    cint.populate_unsigned_int(pid, ruid_addr, ruid)
    cint.populate_unsigned_int(pid, euid_addr, euid)
    cint.populate_unsigned_int(pid, suid_addr, suid)
    apply_return_conditions(pid, syscall_object)


def set_tid_address_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering set_tid_address_entry_handler')
    # POSIX-omni-parser treats this argument as a hex string with no 0x
    # We have to do manual cleanup here
    addr_from_trace = int('0x' + syscall_object.args[0].value, 16)
    addr_from_execution = cint.peek_register(pid, cint.EBX) & 0xffffffff
    logging.debug('Address from trace: %x', addr_from_trace)
    logging.debug('Address from execution: %x', addr_from_execution)
    if addr_from_trace != addr_from_execution:
        raise ReplayDeltaError('Address from trace ({}) does not match '
                               'address from execution ({})'
                               .format(addr_from_trace,
                                       addr_from_execution))


def set_tid_address_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering set_tid_address_exit_handler')
    addr_from_trace = int('0x' + syscall_object.args[0].value, 16)
    tid_from_trace = int(syscall_object.ret[0])
    # We have to use the address from the trace here for two reasons:
    #  1. We already confirmed at the traces matches execution in this regard
    #  in the entry handler
    #  2. Registers have been trashed by this point so we don't have any choice
    logging.debug('Address from trace: %x', addr_from_trace)
    logging.debug('TID from trace: %d', tid_from_trace)
    # We place the TID from the trace into the appropriate memory location
    # so future references are correct
    cint.populate_unsigned_int(pid, addr_from_trace, tid_from_trace)
    apply_return_conditions(pid, syscall_object)


def futex_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering futex entry handler')
    addr_from_trace = int('0x' + syscall_object.args[0].value, 16)
    addr_from_execution = cint.peek_register(pid, cint.EBX) & 0xffffffff
    logging.debug('Address from trace: %x', addr_from_trace)
    logging.debug('Address from execution: %x', addr_from_execution)
    if addr_from_trace != addr_from_execution:
        raise ReplayDeltaError('Address from trace ({}) does not match '
                               'address from execution ({})'
                               .format(addr_from_trace,
                                       addr_from_execution))


def futex_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering futex exit handler')
    ret_val_from_trace = syscall_object.ret[0]
    ret_val_from_execution = cint.peek_register(pid, cint.EAX) & 0xffffffff
    if ret_val_from_trace != ret_val_from_execution:
        raise ReplayDeltaError('Return value from trace ({}) does not match '
                               'return value from execution ({})'
                               .format(ret_val_from_trace,
                                       ret_val_from_execution))


def fadvise64_64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering fadvise_64_64 entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    validate_integer_argument(pid, syscall_object, 1, 1)
    validate_integer_argument(pid, syscall_object, 2, 2)
    if should_replay_based_on_fd(int(syscall_object.args[0].value)):
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Not replaying this system call')


# This handler assumes that uname cannot fail. The only documented way it can
# fail is if the buffer it is handed is somehow invalid. This code assumes that
# well written programs don't do this.
def uname_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering uname handler')
    args = {x.value.split('=')[0]: x.value.split('=')[1]
            for x in syscall_object.args}
    args = {x.strip('{}'): y.strip('"{}') for x, y in args.iteritems()}
    logging.debug(args)
    address = cint.peek_register(pid, cint.EBX)
    noop_current_syscall(pid)
    cint.populate_uname_structure(pid,
                                  address,
                                  args['sysname'],
                                  args['nodename'],
                                  args['release'],
                                  args['version'],
                                  args['machine'],
                                  args['domainname'])
    apply_return_conditions(pid, syscall_object)


def getrlimit_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getrlimit handler')
    cmd = syscall_object.args[0].value[0]
    if cmd != 'RLIMIT_STACK':
        raise Exception('Unimplemented getrlimit command {}'.format(cmd))
    addr = cint.peek_register(pid, cint.ECX)
    rlim_cur = syscall_object.args[1].value.strip('{')
    rlim_cur = rlim_cur.split('=')[1]
    if rlim_cur.find('*') == -1:
        raise Exception('Unimplemented rlim_cur format {}'.format(rlim_cur))
    rlim_cur = int(rlim_cur.split('*')[0]) * int(rlim_cur.split('*')[1])
    rlim_max = syscall_object.args[2].value.strip('}')
    rlim_max = rlim_max.split('=')[1]
    if rlim_max != 'RLIM_INFINITY':
        raise Exception('Unlimited rlim_max format {}'.format(rlim_max))
    rlim_max = 0x7fffffffffffffff
    logging.debug('rlim_cur: %s', rlim_cur)
    logging.debug('rlim_max: %x', rlim_max)
    logging.debug('Address: %s', addr)
    noop_current_syscall(pid)
    cint.populate_rlimit_structure(pid, addr, rlim_cur, rlim_max)
    apply_return_conditions(pid, syscall_object)


def _tcgets_handler(pid, addr, syscall_object):
    c_iflags = syscall_object.args[2].value
    c_iflags = int(c_iflags[c_iflags.rfind('=')+1:], 16)
    c_oflags = syscall_object.args[3].value
    c_oflags = int(c_oflags[c_oflags.rfind('=')+1:], 16)
    c_cflags = syscall_object.args[4].value
    c_cflags = int(c_cflags[c_cflags.rfind('=')+1:], 16)
    c_lflags = syscall_object.args[5].value
    c_lflags = int(c_lflags[c_lflags.rfind('=')+1:], 16)
    c_line = syscall_object.args[6].value
    c_line = int(c_line[c_line.rfind('=')+1:])
    if not ('c_cc' in syscall_object.args[-1].value):
        raise NotImplementedError('Unsupported TCGETS argument format')
    cc = syscall_object.args[-1].value
    cc = cc.split('=')[1].strip('"{}')
    cc = cc.decode('string-escape')
    logging.debug('pid: %s', pid)
    logging.debug('Addr: %s', addr)
    logging.debug('c_iflags: %x', c_iflags)
    logging.debug('c_oflags: %x', c_oflags)
    logging.debug('c_cflags: %x', c_cflags)
    logging.debug('c_lflags: %x', c_lflags)
    logging.debug('c_line: %s', c_line)
    logging.debug('len(cc): %s', len(cc))
    cint.populate_tcgets_response(pid, addr, c_iflags, c_oflags,
                                  c_cflags,
                                  c_lflags,
                                  c_line,
                                  cc)


def _fionread_handler(pid, addr, syscall_object):
    num_bytes = int(syscall_object.args[2].value.strip('[]'))
    logging.debug('Number of bytes: %d', num_bytes)
    cint.populate_int(pid, addr, num_bytes)


def _tiocgwinsz_handler(pid, addr, syscall_object):
    ws_row = syscall_object.args[2].value
    ws_row = int(ws_row.split('=')[1])
    ws_col = syscall_object.args[3].value
    ws_col = int(ws_col.split('=')[1])
    ws_xpixel = syscall_object.args[4].value
    ws_xpixel = int(ws_xpixel.split('=')[1])
    ws_ypixel = syscall_object.args[5].value
    ws_ypixel = int(ws_ypixel.split('=')[1].strip('}'))
    logging.debug('ws_row: %s', ws_row)
    logging.debug('ws_col: %s', ws_col)
    logging.debug('ws_xpixel: %s', ws_xpixel)
    logging.debug('ws_ypixel: %s', ws_ypixel)
    cint.populate_winsize_structure(pid,
                                    addr,
                                    ws_row,
                                    ws_col,
                                    ws_xpixel,
                                    ws_ypixel)


def _fionbio_handler(pid, addr, syscall_object):
    out_val = int(syscall_object.args[2].value.strip('[]'))
    out_addr = cint.peek_register(pid, cint.EDX)
    cint.poke_address(pid, out_addr, out_val)


def _tiocgpgrp_handler(pid, addr, syscall_object):
    pgid = int(syscall_object.args[2].value.strip('[]'))
    logging.debug('Caller PGID: %d,', pgid)
    cint.populate_int(pid, addr, pgid)


def ioctl_entry_handler(syscall_id, syscall_object, pid):
    """Always replay.
    Checks:
    0: int fd: the file descriptor being operated on
    Sets:
    The return value

    Special Action:
    does a variety of things depending on the supplied action


    """
    logging.debug('Entering ioctl handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    trace_fd = int(syscall_object.args[0].value)
    edx = cint.peek_register(pid, cint.EDX)
    logging.debug('edx: %x', edx & 0xffffffff)
    addr = edx
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        cmd = syscall_object.args[1].value
        cmd_from_exe = cint.peek_register(pid, cint.ECX)
        _validate_ioctl_cmd(cmd, cmd_from_exe)
         
        # Alan: optimized ioctl handler
        ioctl_handlers = {
            'TCGETS': _tcgets_handler,
            'FIONREAD': _fionread_handler,
            'FIONBIO': _fionbio_handler,
            'TIOCGWINSZ': _tiocgwinsz_handler,
            'TIOCGPGRP': _tiocgpgrp_handler
           #'TCSETSW', _tcsetsw_handler),
           #'TIOCSWINSZ', _tiocswinsz_handler),
           #'TCSETSF', _tcsetsf_handler),
           #'TCSETS', _tcsets_handler),
           #'FIOCLEX', _fioclex_handler)
        }
        
        # transfer to handler
        try:
            ioctl_handlers[cmd](pid, addr, syscall_object)
        except KeyError:
            raise NotImplementedError("Unsupport ioctl call with %s flag", cmd)

    apply_return_conditions(pid, syscall_object)


def _ioctl_int_to_flag(i):
    f = IOCTLS_INT_TO_IOCTL[i]
    # HACK!
    if f == 'TIOCINQ':
        return ('TIOCINQ', 'FIONREAD')
    else:
        return (f,)


def _validate_ioctl_cmd(cmd_t, cmd_e):
    if 'or' in cmd_t:
        cmd_t = cmd_t.split(' or ')
    else:
        cmd_t = [cmd_t]
    cmd_t = set(cmd_t)
    cmd_e = _ioctl_int_to_flag(cmd_e)
    cmd_e = set(cmd_e)
    if (not (cmd_t <= cmd_e)) and (not (cmd_e <= cmd_t)):
        raise ReplayDeltaError('Command from trace (one of {}) does not match '
                               'command from execution (one of {})'
                               .format(cmd_t, cmd_e))


def prlimit64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering prlimit64 entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    have_new_limit = False
    have_old_limit = False
    if(syscall_object.args[2].value != 'NULL'
       and syscall_object.args[3].value != 'NULL'
       and syscall_object.args[4].value == 'NULL'):
            logging.debug('We have a new limit')
            have_new_limit = True
    elif(syscall_object.args[2].value == 'NULL'
         and syscall_object.args[3].value != 'NULL'
         and syscall_object.args[4].value != 'NULL'):
        logging.debug('We have an old limit')
        have_old_limit = True
    if have_new_limit and not have_old_limit:
        if syscall_object.args[1].value != 'RLIMIT_CORE':
            raise NotImplementedError('prlimit commands with a new limit only '
                                      'support RLIMIT_CORE')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    elif not have_new_limit and have_old_limit:
        if syscall_object.args[1].value != 'RLIMIT_NOFILE':
            raise NotImplementedError('prlimit commands other than '
                                      'RLIMIT_NOFILE are not supported')
        rlim_cur = int(syscall_object.args[3].value.split('=')[1])
        logging.debug('rlim_cur: %d', rlim_cur)
        rlim_max = syscall_object.args[4].value.split('=')[1]
        rlim_max = rlim_max.split('*')
        rlim_max = int(rlim_max[0]) * int(rlim_max[1].strip('}'))
        logging.debug('rlim_max: %d', rlim_max)
        addr = cint.peek_register(pid, cint.ESI)
        logging.debug('addr: %x', addr & 0xFFFFFFFF)
        noop_current_syscall(pid)
        cint.populate_rlimit_structure(pid, addr, rlim_cur, rlim_max)
        apply_return_conditions(pid, syscall_object)
    else:
        raise NotImplementedError('prlimit64 calls with both a new and old '
                                  'limit are not supported')


def mmap2_entry_handler(syscall_id, syscall_object, pid):
    """Never replay
    Checks:
    0: int fd: the file descriptor being operated on
    Sets:
    nothing

    Not Implemented:
    * Determine if there are special cases we should replay

    """
    logging.debug('Entering mmap2 entry handler')
    validate_integer_argument(pid, syscall_object, 1, 1)
    validate_integer_argument(pid, syscall_object, 4, 4)
    fd = syscall_object.args[4].value
    if fd != -1:
        logging.debug('Got non-anonymous mapping')
        print(cint.injected_state['config']['mmap_backing_files'])
        backing_file = cint.injected_state['config']['mmap_backing_files'][str(cint.syscall_index)]
        logging.debug('Selected backing file: %s', backing_file)
        _forge_mmap_with_backing_file(pid, syscall_object, backing_file)


def _forge_mmap_with_backing_file(pid, syscall_object, bf):
    # Preserve the registers mmap uses for parameters
    map_start_addr = int(syscall_object.ret[0], 16)
    logging.debug('Map start address: %x', map_start_addr & 0xffffffff)
    map_size = int(syscall_object.args[1].value)
    logging.debug('Map size: %d', map_size)
    prot = cint.peek_register(pid, cint.EDX)
    # We must make the mapping writable so we can populate it
    prot = prot | 0x2
    flags = cint.peek_register(pid, cint.ESI)
    flags = flags | 0x20 # MAP_ANONYMOUS
    flags = flags | 0x10 # MAP_FIXED
    fd = -1
    offset = 0

    save_EBX  = cint.peek_register(pid, cint.EBX)
    save_ECX  = cint.peek_register(pid, cint.ECX)
    save_EDX  = cint.peek_register(pid, cint.EDX)
    save_ESI  = cint.peek_register(pid, cint.ESI)
    save_EDI  = cint.peek_register(pid, cint.EDI)
    save_EBP  = cint.peek_register(pid, cint.EBP)

    cint.poke_register_unsigned(pid, cint.EBX, map_start_addr)
    # How big of a mapping do we want
    cint.poke_register_unsigned(pid, cint.ECX, map_size)
    # PROT options
    cint.poke_register_unsigned(pid, cint.EDX, prot)
    # Flags options
    cint.poke_register_unsigned(pid, cint.ESI, flags)
    # fd
    cint.poke_register(pid, cint.EDI, fd)
    # offset
    cint.poke_register(pid, cint.EBP, offset)

    # Advance to our crafted mmap's exit
    cint.syscall(pid, 0)
    next_syscall()

    # Copy contents of file into new mapping
    f = open(bf, 'rb')
    data = f.read()
    if len(data) > map_size:
        raise NotImplementedError('Cannot handle cases where backing file is '
                                  'larger than mapping!')
    cint.copy_bytes_into_child_process(pid, map_start_addr, data)

   # restore registers
    cint.poke_register(pid, cint.EBX, save_EBX)
    cint.poke_register(pid, cint.ECX, save_ECX)
    cint.poke_register(pid, cint.EDX, save_EDX)
    cint.poke_register(pid, cint.ESI, save_ESI)
    cint.poke_register(pid, cint.EDI, save_EDI)
    cint.poke_register(pid, cint.EBP, save_EBP)

    # HACK HACK HACK: apply_return_conditions can't handle large addresses
    cint.poke_register_unsigned(pid, cint.EAX, map_start_addr)
    cint.entering_syscall = False


def mmap2_exit_handler(syscall_id, syscall_object, pid):
    """Never replay
    Checks:
    return value: The address of the new memory map
    Sets:
    nothing

    Not Implemented:
    * Determine if there are special cases we should replay

    """
    logging.debug('Entering mmap2 exit handler')
    ret_from_execution = cint.peek_register(pid, cint.EAX)
    ret_from_trace = cleanup_return_value(syscall_object.ret[0])
    logging.debug('Return value from execution %x', ret_from_execution)
    logging.debug('Return value from trace %x', ret_from_trace)
    if ret_from_execution < 0:
        ret_from_execution &= 0xffffffff
    if ret_from_execution != ret_from_trace:
        logging.debug('Return value from execution (%d, %x) differs '
                      'from return value from trace (%d, %x)',
                      ret_from_execution,
                      ret_from_execution,
                      ret_from_trace,
                      ret_from_trace)


def sched_getaffinity_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering sched_getaffinity entry handler')
    # We don't validate the first argument because the PID,
    # which is different for some reason?
    validate_integer_argument(pid, syscall_object, 1, 1)
    try:
        cpu_set_val = int(syscall_object.args[2].value.strip('{}'))
    except ValueError:
        raise NotImplementedError('handler cannot deal with multi-value '
                                  'cpu_sets: {}'
                                  .format(syscall_object.args[2]))
    cpu_set_addr = cint.peek_register(pid, cint.EDX)
    logging.debug('cpu_set value: %d', cpu_set_val)
    logging.debug('cpu_set address: %d', cpu_set_addr)
    noop_current_syscall(pid)
    cint.populate_cpu_set(pid, cpu_set_addr, cpu_set_val)
    apply_return_conditions(pid, syscall_object)


def sigaltstack_entry_handler(syscall_id, syscall_object, pid):
    # This madness is to deal with the fact that the omni-parser
    # messes up argument positions when dealing with structures
    if (syscall_object.args[0].value == 'NULL'
       and syscall_object.args[1].value == 'NULL'):
        have_ss = False
        have_oss = False
    elif (syscall_object.args[0].value == 'NULL'
          and syscall_object.args[1].value != 'NULL'):
            have_ss = False
            have_oss = True
            # Here, oss values are located at 1, 2, 3
            ss_sp = syscall_object.args[1].value
            ss_flags = syscall_object.args[2].value
            ss_size = syscall_object.args[3].value
    elif (syscall_object.args[0].value != 'NULL'
          and syscall_object.args[3].value == 'NULL'):
            have_ss = True
            have_oss = False
    elif (syscall_object.args[0].value != 'NULL'
          and syscall_object.args[3].value != 'NULL'):
            have_ss = True
            have_oss = True
            # here oss values are at 3, 4, 5
            ss_sp = syscall_object.args[3].value
            ss_flags = syscall_object.args[4].value
            ss_size = syscall_object.args[5].value
    else:
        raise ReplayDeltaError('Invalid parse of syscall_object')

    ss_from_execution = cint.peek_register(pid, cint.EBX)
    oss_from_execution = cint.peek_register(pid, cint.ECX)

    # Check for delta
    if ((have_oss and (oss_from_execution == 0))
       or not have_oss and (oss_from_execution != 0)):
        print(oss_from_execution)
        print(have_oss)
        raise ReplayDeltaError('Got non-NULL trace oss and null execution '
                               'oss')
    if ((have_ss and (ss_from_execution == 0))
       or not have_ss and (ss_from_execution != 0)):
        raise ReplayDeltaError('Got non-NULL trace ss and null execution '
                               'ss')

    noop_current_syscall(pid)
    if have_oss:
        # We have an oss so we need to populate the output structure
        # We've gathered the arguments required above but we need to clean them
        # up before we can use them
        ss_sp = int(ss_sp.split('=')[1])
        ss_flags = ss_flags.split('=')[1]
        ss_flags = _cleanup_ss_flags(ss_flags)
        ss_size = int(ss_size.split('=')[1].strip('}'))
        logging.debug('pid: %d', pid)
        logging.debug('addr: %d', oss_from_execution)
        logging.debug('ss_sp: %d', ss_sp)
        logging.debug('ss_flags: %d', ss_flags)
        logging.debug('ss_size: %d', ss_size)
        cint.populate_stack_structure(pid,
                                      oss_from_execution,
                                      ss_sp,
                                      ss_flags,
                                      ss_size)
    apply_return_conditions(pid, syscall_object)


def _cleanup_ss_flags(ss_flags):
    if ss_flags == '0':
        return 0
    else:
        return STACK_SS_TO_INT[ss_flags]


def brk_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to use address: %x',
                  cint.peek_register(pid, cint.EBX))


def mmap2_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to mmap2: %d',
                  cint.peek_register(pid, cint.EDI))


def munmap_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried munmap address: %x length: %d',
                  cint.peek_register(pid, cint.EBX) & 0xFFFFFFFF,
                  cint.peek_register(pid, cint.ECX))


def ioctl_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call used file descriptor: %d',
                  cint.peek_register(pid, cint.EBX))
    logging.debug('This call used command: %s',
                  IOCTLS_INT_TO_IOCTL[
                      cint.peek_register(pid, cint.ECX)])


def rt_sigaction_entry_debug_printer(pid, orig_eax, syscall_object):
    signum = cint.peek_register(pid, cint.EBX)
    newact_addr = cint.peek_register(pid, cint.ECX)
    oldact_addr = cint.peek_register(pid, cint.EDX)
    ret = cint.peek_register(pid, cint.EAX)
    logging.debug("This call has signum: %s", SIGNAL_INT_TO_SIG[signum])
    logging.debug("New act address: 0x%x", newact_addr & 0xffffffff)
    logging.debug("Old act address: 0x%x", oldact_addr & 0xffffffff)
    logging.debug("Return value: %d, ret")


def rt_sigprocmask_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call used command: %s',
                  SIGPROCMASK_INT_TO_CMD[
                      cint.peek_register(pid, cint.EBX)])
