from __future__ import print_function
import pexpect
import tempfile

RR_PROMPT = '\(rr\)'
RR_Y_OR_N = '\(y or n\)'
RR_BP_CREATE_SUCCESS = 'Breakpoint [0-9]+ at 0x[A-Za-z0-9]+:'
RR_BP_CREATE_FAILURE = 'Function ".+" not defined.'
RR_BP_CLEAR_SUCCESS = 'Deleted breakpoint [0-9]+'
RR_BP_CLEAR_FAILURE = 'Function ".+" not defined.'
RR_NO_SYMBOL = 'No symbol ".+" in current context.'
RR_CALL_SUCCESS = 'When the function is done executing, GDB will silently stop.'
RR_EXPRESSION_RESULT = '\$[0-9]+ = \{.+\}\s.+\s<.+>'


def process_preamble(p):
    '''Read to the first (rr) prompt after rr has finished starting up.

    '''

    p.expect('\(rr\)')


def issue_run_command(p, event=None):
    '''Start or restart the application being debugged by issuing the run
    command with no arguments, deal with the (y or n) prompt if
    required, and return when the (rr) prompt is encountered)

    '''

    if event:
        p.sendline('run ' + str(event))
    else:
	p.sendline('run')
    option_found = p.expect([RR_PROMPT, RR_Y_OR_N])
    assert option_found in [0, 1]
    if option_found == 1:
        p.sendline('y')
        p.expect(RR_PROMPT)

def create_breakpoint(p, bp):
    '''Create a breakpoint <bp> using the b <breakpoint> syntax.  Raise an
    exception if the symbol <bp> is undefined or invalid.

    '''
    
    p.sendline('b {}'
               .format(bp))
    option_found = p.expect([RR_BP_CREATE_SUCCESS, RR_BP_CREATE_FAILURE])
    assert option_found in [0, 1]
    if option_found == 1:
        raise RuntimeError('Failed to create breakpoint {}.'
                           .format(bp))
    p.expect(RR_PROMPT)


def clear_breakpoint(p, bp):
    '''Clear the breakpoint <bp using the clear <breakpoint syntax.
    Raise an exception if the symbol <bp> is undefined or invalid.

    '''

    p.sendline('clear {}'
               .format(bp))
    option_found = p.expect([RR_BP_CLEAR_SUCCESS, RR_BP_CLEAR_FAILURE])    
    assert option_found in [0, 1]
    if option_found == 1:
        raise RuntimeError('Failed to clear breakpoint {}.'
                           .format(bp))
    p.expect(RR_PROMPT)

def call_function(p, func):
    '''Call a functin using the call <function> syntax.
   
    ''' 

    p.sendline('call {}'
               .format(func))
    option_found = p.expect([RR_CALL_SUCCESS, RR_EXPRESSION_RESULT, RR_NO_SYMBOL])
    assert option_found in [0, 1, 2]
    if option_found in [1, 2]:
        raise RuntimeError('Failed to call function {}.  See log for details.'
                           .format(func))
    p.expect(RR_PROMPT) 


def continue_execution(p):
    '''Continue execution until the next stopping point using the
    'continue' command

    '''

    p.sendline('continue')
    p.expect(RR_PROMPT)


def init(outfile=None):
    '''Initialize pexpect's process handle with appropriate timeout
    and logfile

    '''

    outfile = open(outfile, 'wb') if outfile else tempfile.TemporaryFile(mode='wb')
    return pexpect.spawn('/usr/local/bin/rr replay -a',
                         logfile=outfile,
                         timeout=None)
        

if __name__ == '__main__':
    f = open('out.log', 'wb')
    p = init('out.log')
    process_preamble(p)
    issue_run_command(p)
    create_breakpoint(p, 'main')
    call_function(p, 'main()')
    clear_breakpoint(p, 'main')
