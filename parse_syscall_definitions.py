"""
<Started>
  June 2013

<Author>
  Savvas Savvides <savvas@purdue.edu>

<Purpose>
  Parse the definitions of all system calls from their man pages.

  First read the manual page for syscalls (man 2 syscalls) and parse the names
  of all system calls available in the system. Then for each system call read
  its man page and get its definition.


  Manual pages (man) are read using the subprocess library.


  Example running this program:
    run:
      python parse_syscall_definitions.py

    - several different views are provided. read the main method at the end of
    this file and uncomment appropriately.

    - the option of saving the system call definitions to a pickle file is also
    provided.

"""

import re
import signal
import subprocess

from sysDef.SyscallManual import SyscallManual


def parse_syscall_names_list():
    """
    <Purpose>
      Reads the man entry for 'syscalls' and parses all the names of the system 
      calls in the system.
    
    <Arguments>
      None
    
    <Exceptions>
      None
    
    <Side Effects>
      None
    
    <Returns>
      syscall_names_list: 
        A list of all the system call names gathered from the man page of the 
        syscalls man entry.
    """



    # read the man page for 'syscalls' into a byte string.
    #
    # https://blog.nelhage.com/2010/02/a-very-subtle-bug/
    # read link for supporting this operation on python v2. python v3 fixes this so the second
    # argument of check_output is not needed.
    man_page_bytestring = subprocess.check_output(['man', 'syscalls'], preexec_fn=lambda:
                      signal.signal(signal.SIGPIPE, signal.SIG_DFL))

    # cast to string and split into a list of lines.
    man_page_lines = man_page_bytestring.decode("utf-8").split("\n")

    # a regular expression used to sanitize the read lines. Specifically removes
    # the backspace characters and the character they hide to allow searching for
    # substrings.
    char_backspace = re.compile(".\b")

    # remove all lines until the line with the first system call which includes
    # the text "_llseek(2)" on a GNU/Linux 3.5.0-36-generic
    while True:
        if len(man_page_lines) == 0:
            raise Exception("_llseek not found in syscalls man page.")

        line = man_page_lines[0]

        # line could include backspaces \b which prevents from searching the line
        # correctly. Remove backspaces.
        # eg: # __llllsseeeekk(2)                  1.2
        line = char_backspace.sub("", line)

        if "_llseek(2)" in line:
            break

        # if this is not the line we are looking for then remove the line and
        # continue.
        man_page_lines.pop(0)

    # At this point the first item in man_page_lines should contain the name of
    # the first system call. Get the names of all system calls up to the last one
    # which should be the "writev" system call.
    syscall_names_list = []

    # loop until the last entry of the list of syscall names is writev.
    while True:
        if len(man_page_lines) == 0:
            raise Exception("Reached the end of syscalls man page while trying to " +
                          "read the syscall names.")

        line = man_page_lines.pop(0).strip()

        # sanitize line (remove backspaces)
        line = char_backspace.sub("", line)

        # skip empty lines.
        if(line == ''):
            continue

        # we only need the name of the system call which should be the first part of
        # the line.
        #
        # Example lines in syscalls man entry:
        # afs_syscall(2)                            Not implemented
        # alarm(2)
        # alloc_hugepages(2)          2.5.36        Removed in 2.5.44
        # perf_event_open(2)          2.6.31        Was called perf_counter_open()
        #                                           in 2.6.31; renamed in 2.6.32
        syscall_name = line.split(None, 1)[0].strip()

        # all syscall names are followed by the "(2)" text. if not then they must be
        # something else we don't need, so let's skip it.
        if(not syscall_name.endswith("(2)")):
            continue

        # remove the "(2)" part and add it to the list.
        syscall_name = syscall_name[:syscall_name.find("(2)")]
        syscall_names_list.append(syscall_name)


        # once we add the writev syscall we break since there are no more syscalls
        # after this.
        if(syscall_name == "writev"):
            break

    return syscall_names_list



def get_syscall_definitions_list(syscall_names_list):
    """
    <Purpose>
      Given a list of syscall names, it returns a list of SyscallManual  objects.
    
    <Arguments>
      syscall_names_list:
        a list of system call names.
    
    <Exceptions>
      None
    
    <Side Effects>
      None
    
    <Returns>
      syscall_definitions_list:
        A list of SyscallManual objects.
    
    """
    syscall_definitions_list = []
    for syscall_name in syscall_names_list:
        syscall_definitions_list.append(SyscallManual(syscall_name))

    return syscall_definitions_list



def print_definitions1(syscall_definitions_list):
    """
    A view of the parsed definitions. Prints the number of system call names 
    parsed, the list of all the system call names and a list of all the 
    definitions.
    """

    print "A total of", len(syscall_definitions_list), "system call names were parsed."
    print
    print

    print"List of system call names:"
    print"--------------------------"

    for sd in syscall_definitions_list:
        print sd.name

    print
    print

    print "List of system call definitions:"
    print "--------------------------------"


    for sd in syscall_definitions_list:
        print sd
        print

    print
    print



def print_definitions2(syscall_definitions_list):
    """
    A view of the parsed definitions. Prints only the list of parsed definitions. 
    Skips the system calls for which a definition was not found (for any reason).
    """

    print "List of all syscall definitions found"
    print "====================================="
    for sd in syscall_definitions_list:
        if(sd.type == SyscallManual.FOUND):
            print sd.definition

    print
    print



def print_definitions3(syscall_definitions_list):
    """
    A view of the parsed definitions. 
    - Lists the syscall names for which a definition was NOT found.
    - Prints the reason the definition was not found.
    - Lists the type of all syscalls i.e:
        - found
        - no manual page
        - not found in manual page
        - unimplemented system call.
    """

    print "List of all syscall names for which a definition was not found"
    print "=============================================================="
    for sd in syscall_definitions_list:
        if(sd.type != SyscallManual.FOUND):
            print sd.name

    print
    print

    # remember the type of each syscall to provide statistics at the end.
    found = []
    no_man = []
    not_found = []
    unimplemented = []

    print "Syscall names and the reason its definition was not found"
    print "========================================================="
    for sd in syscall_definitions_list:
        if(sd.type == SyscallManual.FOUND):
            found.append(sd.name)
            continue
        elif(sd.type == SyscallManual.NO_MAN_ENTRY):
            no_man.append(sd.name)
        elif(sd.type == SyscallManual.NOT_FOUND):
            not_found.append(sd.name)
        else:    # unimplemented
            unimplemented.append(sd.name)

        print sd
        print

    print

    print str(len(found)) + " syscall definitions found"
    print "-----------------------------"
    for name in found:
        print name

    print
    print

    print str(len(no_man)) + " syscall definitions with no manual entry"
    print "-------------------------------------------"
    for name in no_man:
        print name

    print

    print str(len(not_found)) + " definitions not found in their man entry"
    print "-------------------------------------------"
    for name in not_found:
        print name

    print

    print str(len(unimplemented)) + " system calls identified as unimplemented"
    print "-------------------------------------------"
    for name in unimplemented:
        print name

    print
    print



def pickle_syscall_definitions(syscall_definitions_list):
    """
    Store the syscall_definitions_list into a pickle file.
    """

    import pickle
    pickle_name = "syscall_definitions.pickle"
    pickle_file = open(pickle_name, 'wb')
    pickle.dump(syscall_definitions_list, pickle_file)
    pickle_file.close()




def main():

    # get a list with all the system call names available in this system.
    syscall_names_list = parse_syscall_names_list()

    # use the list of names just parsed to generate a list of system call
    # definitions.
    syscall_definitions_list = get_syscall_definitions_list(syscall_names_list)

    # different views:
    print_definitions1(syscall_definitions_list)
    print_definitions2(syscall_definitions_list)
    print_definitions3(syscall_definitions_list)

    # pickle syscall_definitions_list
    pickle_syscall_definitions(syscall_definitions_list)

if __name__ == "__main__":
    main()
