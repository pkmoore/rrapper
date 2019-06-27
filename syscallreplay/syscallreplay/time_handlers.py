# pylint: disable=missing-docstring, unused-argument, invalid-name
"""
<Program Name>
  time_handlers

<Purpose>
  Provide system call handlers that pertain to low-level timing operations

"""

import logging
import time

import util


def timer_create_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    timer_create call entry handler that replays based on the return value.
    It does several things:
    1. Check to see if return value is successful (0)
    2. Check sigevent to be SIGEV_NONE
    3. Retrieve timerid address from EDX register
    4. Populate the timer_t structure with parameters
    5. Noop the current system call
    5. Set the return value

    Checks:
    1: struct sigevent *sevp: how to noify the expiration of the timer
    2. timer_t *timerid: returned timer_t pointer that identifies the timer.
    return value

    Sets:
    2: timer_t *timerid
    return value
    errno

  <Returns>
    None

  """
  logging.debug("Entering the timer_create entry handler")
  if syscall_object.ret[0] == -1:
    raise NotImplementedError('Unsuccessful calls not implemented')
  else:
    # only SIGEV_NONE is supported as other sigevents can't be replicated as of now
    sigev_type = syscall_object.args[3].value.strip()
    logging.debug("Sigevent type: %s", str(sigev_type))

    if sigev_type != 'SIGEV_NONE':
      raise NotImplementedError("Sigevent type %s is not supported" % (sigev_type))

    addr = util.cint.peek_register(pid, util.cint.EDX)
    logging.debug('timerid address: %x', addr)

    timerid = int(syscall_object.args[-1].value.strip('{}'))
    logging.debug(str(timerid))

    util.cint.populate_timer_t_structure(pid, addr, timerid)

    util.noop_current_syscall(pid)
    util.apply_return_conditions(pid, syscall_object)





def timer_extract_and_populate_itimerspec(syscall_object, pid, addr, start_index):
  """
  <Purpose>
    Helper method that extracts attributes of a `struct itimerspec`
    parameter and populates the structure.

  <Returns>
    None

  """
  logging.debug('Itimerspec Address: %x', addr)
  logging.debug('Extracting itimerspec')

  i = start_index
  interval_seconds = int(syscall_object.args[i].value.split("{")[2].strip())
  interval_nanoseconds = int(syscall_object.args[i+1].value.strip('{}'))
  logging.debug('Interval Seconds: %d', interval_seconds)
  logging.debug('Interval Nanoseconds: %d', interval_nanoseconds)

  value_seconds = int(syscall_object.args[i+2].value.split("{")[1].strip())
  value_nanoseconds = int(syscall_object.args[i+3].value.strip('{}'))
  logging.debug('Value Seconds: %d', value_seconds)
  logging.debug('Value Nanoseconds: %d', value_nanoseconds)

  logging.debug('Populating itimerspec structure')
  util.cint.populate_itimerspec_structure(pid, addr,
                                     interval_seconds, interval_nanoseconds,
                                     value_seconds, value_nanoseconds)





def timer_settime_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    timer_settime call entry handler that replays based on the return value.
    It does several things:
    1. Check if the return value is successful (0)
    2. Check if old_value parameter is present.
    If old_value is present:
        3. Extract and populate the itimerspec structure
    3. Noop out the current system call
    5. Set the return value

    Checks:
    3: struct itimerspec *old_value
    return value

    Sets:
    3: struct itimerspec *old_value
    return value
    errno

  <Returns>
    None

  """
  logging.debug("Entering the timer_settime entry handler")
  if syscall_object.ret[0] == -1:
    raise NotImplementedError('Unsuccessful calls not implemented')
  else:
    logging.debug(str(syscall_object.args[-1]))
    old_value_present = syscall_object.args[-1].value != 'NULL'
    if old_value_present:
      logging.debug("Old value present, have to copy it into memory")

      addr = util.cint.peek_register(pid, util.cint.ESI)
      logging.debug('old_value address: %x', addr)

      itimerspec_starting_index = 6
      timer_extract_and_populate_itimerspec(syscall_object,
                                            pid,
                                            addr,
                                            itimerspec_starting_index)

    util.noop_current_syscall(pid)
    util.apply_return_conditions(pid, syscall_object)





def timer_gettime_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    timer_gettime call entry handler that replays based on return value.
    It does several things:
    1. Check if the return value is successful (0)
    2. Check if the timer_id from trace is different from execution
    4. Retrieve the addr parameter from the ECX register
    5. Populate the itimerspec structure
    6. Noop out the current system call
    7. Set the return value

    Checks:
    0: timer_t timerid
    return value

    Sets:
    3: struct itimerspec *old_value
    return value
    errno

  <Returns>
    None

  """
  logging.debug("Entering the timer_gettime entry handler")
  if syscall_object.ret[0] == -1:
    raise NotImplementedError('Unsuccessful calls not implemented')
  else:
    logging.debug('Got successful timer_gettime call')
    logging.debug('Replaying this system call')

    # these should be the same probably?
    timer_id_from_trace = int(syscall_object.args[0].value[0].strip('0x'))
    timer_id_from_execution = int(util.cint.peek_register(pid, util.cint.EBX))

    if timer_id_from_trace != timer_id_from_execution:
      raise util.ReplayDeltaError("Timer id ({}) from execution "
                             "differs from trace ({})"
                             .format(timer_id_from_execution, timer_id_from_trace))

    addr = util.cint.peek_register(pid, util.cint.ECX)
    itimerspec_starting_index = 1
    timer_extract_and_populate_itimerspec(syscall_object, pid, addr, itimerspec_starting_index)
    util.noop_current_syscall(pid)
    util.apply_return_conditions(pid, syscall_object)





def timer_delete_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    timer_delete call entry handler.

    TODO: add functionality:
      * check return value
      * check timer_id in trace and execution

  <Returns>
    None

  """
  logging.debug("Entering the timer_delete entry handler")
  util.noop_current_syscall(pid)
  util.apply_return_conditions(pid, syscall_object)





def time_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    time call entry handler that always replays. It does several
    things:
    1. Check if the return value is successful (0)
    2. Retrieve the addr of the time_t structure in the EBX register
    3. Noop out the current system call
    4. Populate the time_t parameter
    5. Set the return value

    Checks:
    return value

    Sets:
    return value: The time or -1 (error)
    0:The the value of the integer pointed to by 0, if not NULL
    errno

  <Returns>
    None

  """
  logging.debug('Entering time entry handler')
  if syscall_object.ret[0] == -1:
    raise NotImplementedError('Unsuccessful calls not implemented')
  else:
    addr = util.cint.peek_register(pid, util.cint.EBX)
    util.noop_current_syscall(pid)
    logging.debug('Got successful time call')
    t = int(syscall_object.ret[0])
    logging.debug('time: %d', t)
    logging.debug('addr: %d', addr)
    if syscall_object.args[0].value != 'NULL' or addr != 0:
      logging.debug('Populating the time_t')
      util.cint.populate_unsigned_int(pid, addr, t)
    util.apply_return_conditions(pid, syscall_object)





def time_forger(pid):
  """
  <Purpose>
    Forge a time() call based on injected state.

    Checks:
    Nothing

    Sets:
    return value: The time or -1 (error)
    0:The the value of the integer pointed to by 0, if not NULL
    errno

  <Returns>
    None

  """
  logging.debug('Forging time call')
  t = util.cint.injected_state['times'][-1]
  times = util.cint.injected_state['times']
  new_t = t + _get_avg_time_result_delta(times)
  util.cint.injected_state['times'].append(new_t)
  syscall_object = lambda: None
  syscall_object.name = 'time'
  syscall_object.ret = []
  syscall_object.ret.append(t)
  addr = util.cint.peek_register(pid, util.cint.EBX)
  if addr != 0:
    util.cint.populate_unsigned_int(pid, addr, t)
  util.noop_current_syscall(pid)
  util.apply_return_conditions(pid, syscall_object)
  # Back up one system call we passed it when we decided to forge this
  # call
  util.cint.syscall_index -= 1





def gettimeofday_forger(pid):
  """
  <Purpose>
    Forge a gettimeofday call based on injected state

    Checks:
    1: struct timezone *tz

    Sets:
    return value
    errno

  <Returns>
    None

  """
  logging.debug('Forging gettimeofday call')
  timezone_addr = util.cint.peek_register(pid, util.cint.ECX)
  if timezone_addr != 0:
    raise NotImplementedError('Cannot forge gettimeofday() with a timezone')
  time_addr = util.cint.peek_register(pid, util.cint.EBX)
  seconds_times = [x['seconds']
               for x in util.cint.injected_state['gettimeofdays']]
  microseconds_times = [x['microseconds']
                    for x in util.cint.injected_state['gettimeofdays']]
  if not seconds_times and not microseconds_times:
    seconds_delta = _get_avg_time_result_delta(seconds_times)
    microseconds_delta = _get_avg_time_result_delta(microseconds_times)
    last_seconds = util.cint.injected_state['gettimeofdays'][-1]['seconds']
    last_microseconds = util.cint.injected_state['gettimeofdays'][-1]['microseconds']
    seconds = last_seconds + seconds_delta
    microseconds = last_microseconds + microseconds_delta
  else:
    seconds = int(time.time())
    microseconds = 0
  util.cint.injected_state['gettimeofdays'].append({'seconds': seconds,
                                           'microseconds': microseconds})
  logging.debug('Using seconds: %d microseconds: %d', seconds, microseconds)
  syscall_object = lambda: None
  syscall_object.name = 'gettimeofday'
  syscall_object.ret = []
  syscall_object.ret.append(0)
  util.noop_current_syscall(pid)
  util.cint.populate_timeval_structure(pid, time_addr, seconds, microseconds)
  util.apply_return_conditions(pid, syscall_object)
  # Back up one system call we passed it when we decided to forge this
  # call
  util.cint.syscall_index -= 1





def _get_avg_time_result_delta(times):
  """
  <Purpose>
    Helper function that retrieves a dict of time
    deltas and returns an average

  <Returns>
    1000 or
    average of times from deltas

  """
  
  deltas = []
  for i, _ in enumerate(times):
    if i == 0:
      continue
    deltas.append(times[i] - times[i-1])
  if deltas:
    # We don't have enough to do averages so start with 10
    return 1000
  return reduce(lambda x, y: x + y, deltas) / len(deltas)





def gettimeofday_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    gettimeofday call entry handler that replays based on the return value.
    It does several things:
    1. Check if the return value is successful (0)
    2. Noop out the current system call
    3. Populate the timeval structur
    4. Set the return value

    Checks:
    return value

    Sets:
    0: struct timeval *tv
    return value
    errno

  <Returns>
    None

  """
  logging.debug('Entering gettimeofday entry handler')
  if syscall_object.ret[0] == -1:
    raise NotImplementedError('Unsuccessful calls not implemented')
  elif syscall_object.args[2].value != 'NULL':
      raise NotImplementedError('time zones not implemented')
  else:
    util.noop_current_syscall(pid)
    addr = util.cint.peek_register_unsigned(pid, util.cint.EBX)
    seconds = syscall_object.args[0].value.strip('{}, ')
    # gettimeofday() call might have the tv_sec and tv_usec labels in the
    # output structure.  If it does, we need to split() it off.
    if 'tv_sec' in seconds:
      seconds = seconds.split('=')[1]
    seconds = int(seconds)
    # gettimeofday() call might have the tv_sec and tv_usec labels in the
    # output structure.  If it does, we need to split() it off.
    microseconds = syscall_object.args[1].value.strip('{}')
    if 'tv_usec' in microseconds:
      microseconds = microseconds.split('=')[1]
    microseconds = int(microseconds)
    logging.debug('Address: %x', addr)
    logging.debug('Seconds: %d', seconds)
    logging.debug('Microseconds: %d', microseconds)
    logging.debug('Populating timeval structure')
    util.cint.populate_timeval_structure(pid, addr, seconds, microseconds)
    util.apply_return_conditions(pid, syscall_object)





def clock_gettime_forger(pid):
  """
  <Purpose>
    Forge a clock_gettime call based on injected state.

  <Returns>
    None

  """
  logging.debug('Entering clock_gettime_forger')
  clock_type = util.cint.peek_register_unsigned(pid, util.cint.EBX)
  timespec_addr = util.cint.peek_register_unsigned(pid, util.cint.ECX)
  if clock_type != 1:
    raise NotImplementedError('Cannot forge non-CLOCK_MONOTONIC calls')
  seconds = util.cint.injected_state['clock_gettimes'][-1]['seconds'] + 1
  nanoseconds = util.cint.injected_state['clock_gettimes'][-1]['nanoseconds']
  logging.debug('Seconds: %d', seconds)
  logging.debug('Nanoseconds: %d', nanoseconds)
  util.noop_current_syscall(pid)
  util.cint.populate_timespec_structure(pid, timespec_addr, seconds, nanoseconds)
  util.cint.syscall_index -= 1





def clock_gettime_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    clock_gettime call entry handler that replays based on the return value.
    It does several things:
    1. Check the return value to be successful (0)
    2. Noop out the current system call
    3. Check clock type from trace and execution
    4. Populate timespec structure
    5. Set return value

    Checks:
    return value

    Sets:
    1: struct timespec *res
    return value
    errno

  <Returns>
    None

  """
  logging.debug('Entering clock_gettime entry handler')
  if syscall_object.ret[0] == -1:
    raise NotImplementedError('Unsuccessful calls not implemented')
  else:
    logging.debug('Got successful clock_gettime call')
    logging.debug('Replaying this system call')
    util.noop_current_syscall(pid)
    clock_type_from_trace = syscall_object.args[0].value
    clock_type_from_execution = util.cint.peek_register(pid,
                                                 util.cint.EBX)
    # The first arg from execution must be CLOCK_MONOTONIC
    # The first arg from the trace must be CLOCK_MONOTONIC
    if clock_type_from_trace == 'CLOCK_MONOTONIC':
      if clock_type_from_execution != util.cint.CLOCK_MONOTONIC:
        raise util.ReplayDeltaError('Clock type ({}) from execution '
                                 'differs from trace'
                                 .format(clock_type_from_execution))
    if clock_type_from_trace == 'CLOCK_PROCESS_CPUTIME_ID':
      if clock_type_from_execution != util.cint.CLOCK_PROCESS_CPUTIME_ID:
        raise util.ReplayDeltaError('Clock type ({}) from execution '
                                 'differs from trace'
                                 .format(clock_type_from_execution))
    # clock_gettime() call might have the tv_sec and tv_nsec labels in the
    # output structure.  If it does, we need to split() it off.
    seconds = syscall_object.args[1].value.strip('{}')
    if 'tv_sec' in seconds:
      seconds = seconds.split('=')[1]
    seconds = int(seconds)
    nanoseconds = syscall_object.args[2].value.strip('{}')
    if 'tv_nsec' in nanoseconds:
      nanoseconds = nanoseconds.split('=')[1]
    nanoseconds = int(nanoseconds)
    addr = util.cint.peek_register(pid, util.cint.ECX)
    logging.debug('Seconds: %d', seconds)
    logging.debug('Nanoseconds: %d', nanoseconds)
    logging.debug('Address: %x', addr)
    logging.debug('Populating timespec strucutre')
    util.cint.populate_timespec_structure(pid,
                                   addr,
                                   seconds,
                                   nanoseconds)
    util.apply_return_conditions(pid, syscall_object)





def times_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    times call entry handler that always replays. It does several things:
    1. Noop out the current system call
    2. Populate the tms structure
    3. Set the return value
    
    Checks: 
    nothing

    Sets: 
    contents of the structure passed as a parameter
    errno

  <Returns>
    None

  """
  logging.debug('Entering times entry handler')
  util.noop_current_syscall(pid)
  if syscall_object.args[0].value != 'NULL':
    logging.debug('Got times() call with out structure supplied')
    addr = util.cint.peek_register(pid, util.cint.EBX)
    utime = int(syscall_object.args[0].value.split('=')[1])
    logging.debug('utime: %d', utime)
    stime = int(syscall_object.args[1].value.split('=')[1])
    logging.debug('stime: %d', stime)
    cutime = int(syscall_object.args[2].value.split('=')[1])
    logging.debug('cutime: %d', cutime)
    cstime = int(syscall_object.args[3].value.split('=')[1].rstrip('}'))
    logging.debug('cstime: %d', cstime)
    util.cint.populate_tms_structure(pid, addr, utime, stime, cutime, cstime)
  util.apply_return_conditions(pid, syscall_object)





def utimensat_entry_handler(syscall_id, syscall_object, pid):
  """
  <Purpose>
    utimensat call entry handler that always replays. It does
    several things:
    1. Check if AT_FDCWD flag was passed, if not, validate
    flag passed
    2. Noop out the current system call
    
    TODO: replay execution behavior

  <Returns>
    None

  """
  logging.debug('Entering utimensat entry handler')
  if syscall_object.args[0].value != 'AT_FDCWD':
    util.validate_integer_argument(pid, syscall_object, 0, 0)
  util.noop_current_syscall(pid)
  logging.debug('Replaying this system call')
  # This code is commented out because I don't think these are out addresses.
  # That is, the kernel doesn't modify anything in the array.  This is a
  # "return success" situation.
  #timespec0_addr = util.cint.peek_register_unsigned(pid, util.cint.EDX)
  #timespec1_addr = timespec0_addr + 8
  #logging.debug('Timespec 0 addr: %x', timespec0_addr)
  #logging.debug('Timespec 1 addr: %x', timespec1_addr)
  #timespec0_seconds = syscall_object.args[2].value
  #timespec0_seconds = int(timespec0_seconds.strip('[]{}'))
  #timespec0_nseconds = syscall_object.args[3].value[0]
  #timespec0_nseconds = int(timespec0_nseconds.rstrip('[]{}'))
  #logging.debug('Timespec0 seconds: %d nseconds: %d',
  #            timespec0_seconds,
  #            timespec0_nseconds)
  #timespec1_seconds = syscall_object.args[4].value
  #timespec1_seconds = int(timespec1_seconds.strip('[]{}'))
  #timespec1_nseconds = syscall_object.args[5].value
  #timespec1_nseconds = int(timespec1_nseconds.rstrip('[]{}'))
  #logging.debug('Timespec1 seconds: %d nseconds: %d',
  #            timespec1_seconds,
  #            timespec1_nseconds)
  #util.cint.populate_timespec_structure(pid,
  #                               timespec0_addr,
  #                               timespec0_seconds,
  #                               timespec0_nseconds)
  #util.cint.populate_timespec_structure(pid,
  #                               timespec1_addr,
  #                               timespec1_seconds,
  #                               timespec1_nseconds)
  util.apply_return_conditions(pid, syscall_object)





def time_entry_debug_printer(pid, orig_eax, syscall_object):
  """
  <Purpose>
    Debug printing method for time-related method calls.

  <Returns>
    None

  """
  param = util.cint.peek_register(pid, util.cint.EBX)
  if param == 0:
    logging.debug('Time called with a NULL time_t')
  else:
    logging.debug('time_t addr: %d', param)
