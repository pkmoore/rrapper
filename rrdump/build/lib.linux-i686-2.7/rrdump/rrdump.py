"""
Supplies functions to be called from within rr to handle collecting and
exporting state needed within the CrashSim Injector
"""

from __future__ import print_function
import json
import os
import os.path


state_dict = {}
state_dict['open_fds'] = {}
state_dict['syscalls_made'] = []
state_dict['times'] = []
state_dict['brks'] = []
state_dict['gettimeofdays'] = []
state_dict['clock_gettimes'] = []
proc_pipe = None
proc_pipe_name = 'rrdump_proc.pipe'

def write_to_pipe(data):
    global proc_pipe
    if not proc_pipe:
        if os.path.exists(proc_pipe_name):
            os.unlink(proc_pipe_name)
        os.mkfifo(proc_pipe_name)
        proc_pipe = open(proc_pipe_name, 'w', 0)
    proc_pipe.write(data)

def close_pipe():
    global proc_pipe
    proc_pipe.close()

# Always call process syscall, have a field set in the dictionary passed in taht
# is a list of 'new fds'

# We track the fact that we don't know the tid of the first process to execute.
# All other processes come from this one so we only need to initialize fds for
# this one.  The rest of the processes created will derive their file
# descriptors from this one.

initial_tid = None

def process_syscall(state):
    global initial_tid
    global state_dict
    if not initial_tid:
        initial_tid = state['rec_tid']
        state_dict['open_fds'][initial_tid] = [0, 1, 2]

    # Handle clone
    if state['name'] == 'clone' and not state['entering']:
        clone_flags = state['arg1_unsigned']
        clone_files = (clone_flags & 0x00000400) == 0x00000400
        new_proc = state['result']
        if clone_files:
            state_dict['open_fds'][new_proc] = state_dict['open_fds'][state['rec_tid']]
        else:
            state_dict['open_fds'][new_proc] = state_dict['open_fds'][state['rec_tid']][:]

    state_dict['syscalls_made'].append(state)

def process_brk(flags, start, size, prot):
    state_dict['brks'].append({'flags': flags,
                               'start': start,
                               'size': size,
                               'prot': prot})

def process_gettimeofday(seconds, microseconds):
    state_dict['gettimeofdays'].append({'seconds': seconds,
                                        'microseconds': microseconds})

def process_clock_gettime(clock_id, seconds, nanoseconds):
    state_dict['clock_gettimes'].append({'clock_id': clock_id,
                                         'seconds': seconds,
                                         'nanoseconds': nanoseconds})
def process_time(time):
    state_dict['times'].append(time)

def dump_state(event):
    name = str(event) + '_state.json'
    with open(name, 'w') as f:
        json.dump(state_dict, f)
