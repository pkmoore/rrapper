class NullChecker:
    """Null checker.  Is always in an accepting state and does not transition.
    """
    def __init__(self):
        pass

    def transition(self, syscall_object):
        pass

    def is_accepting(self):
        return True


# This checker determines whether or not the application under test checks to
# make sure the source file hasn't changed during the copy process. To pass,
# the application must have called stat64 or lstat64 on the source followed by
# a call to open on the source, and a call to fstat64 on the file descriptor
# returned by the open call.


class DontReadFifoChecker:
    """ Detect the situation where an application stats a file, fails to realize
        that it is a FIFO, and attempts to continue execution as normal.
        1. Application must not read from the file

        Limitations: only sees calls to stat64. Need to support fstat64 flow

    """
    def __init__(self, filename):
        self.filename = filename
        self.fifo_checker = DontReadFileAfterStatChecker(filename)

    def transition(self, syscall_object):
        self.fifo_checker.transition(syscall_object)

    def is_accepting(self):
        return self.fifo_checker.is_accepting()


class MTUIssueChecker:
    """ Detect the situation where a client does not read all the data it is
        expected to read from a socket.
        1. A connect() call must be made to the target IP address and port
        2. Data must be repeatedly read from the connected socket until it has
        all be read

        Injection: Make select return 0, application should continue trying
        receive datapi

        limitations: only looks at the FIRST connection to a given ip:port
        Adding additional SocketConnectedAndReadCheckers can deal with simple
        multi-connection situations. A more robust solution is needed for more
        complex situations.
        If you specify a small number of expected bytes, the data_length
        parameter, this will almost always pass as the amount read must be
        GREATER THAN the expected amount, not exactly equal to.
    """
    def __init__(self, addr, port, data_length):
        self.addr = addr
        self.port = port
        self.data_length = data_length
        self.receive_checker = SocketConnectedAndReadChecker(self.addr,
                                                             self.port,
                                                             self.data_length)

    def transition(self, syscall_object):
        self.receive_checker.transition(syscall_object)

    def is_accepting(self):
        return self.receive_checker.is_accepting()


class CopySymlinkOverTargetChecker:
    """ Detect the case where an application tries to copy a symlink over its
        target.
        1. Source must be lstat()'d
        2. Must not call unlink on destination
        3. Must not open destination destructively
    """
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.src_checker = AtLeastOnceWithArgAutomaton('lstat64',
                                                       self.src,
                                                       0)
        self.dst_write_checker = DontModifyFileAutomaton(dst)
        self.dst_unlink_checker = AtLeastOnceWithArgAutomaton('unlink',
                                                              self.dst,
                                                              0)

    def transition(self, syscall_object):
        self.src_checker.transition(syscall_object)
        self.dst_write_checker.transition(syscall_object)
        self.dst_unlink_checker.transition(syscall_object)

    def is_accepting(self):
        return (self.src_checker.is_accepting()
                and self.dst_write_checker.is_accepting()
                and not self.dst_unlink_checker.is_accepting())


class CopyUrandomIncorrectlyChecker:
    """ Detect the case where an application tries to copy the urandom device as
        if it were a normal file (i.e. open, read, write etc.)
        1. The file must not read from urandom and write the data out to the
        destination file verbatim

        Accepting trace: none -> moving a special file requires root permissions
        Rejecting trace: mmv_crossdisk_urandom_small.strace

        Limitations: Will reject applications that are copying /dev/urandom to a
        file even though this may be valid behavior for some applications.
    """
    def __init__(self):
        self.copy_automaton = UrandomReadDuringCopyAutomaton()

    def transition(self, syscall_object):
        self.copy_automaton.transition(syscall_object)

    def is_accepting(self):
        print(self.copy_automaton.current_state)
        return self.copy_automaton.is_accepting()


class FileReplacedDuringCopyChecker:
    """ Detect the case where an application fails to use fstat() to detect when
        the source file changes at some point after it was stat()'d
        1. The file must be stat()'d
        2. The file must be opened
        3. The file must be fstat()'d

        Accepted trace: mmv_crossdisk.strace
        Rejected trace: mv_crossdisk_xattrs.strace

    """
    def __init__(self, filename):
        self.filename = filename
        self.source_automaton = StatOpenFstatAutomaton(self.filename)

    def transition(self, syscall_object):
        self.source_automaton.transition(syscall_object)

    def is_accepting(self):
        return self.source_automaton.is_accepting()


class XattrsCopiedDuringCopyChecker:
    """ Detect the case where a files extended file attributes are lost during a
        cross disk move because the application does not manually copy them from
        the source file to the destination file
        1. The source file must be opened
        2. Some number of extended attributes must be read with fgetxattr
        3. All of the previously read extended attributes must be applied to the
        destination file with fsetxattr

        Accepted trace: mv_crossdisk_xattrs.strace
        Rejected trace: mmv_crossdisk.strace

        Limitations: Will reject if attributes are not read all at once and
        then written all at once.

    """
    def __init__(self, filename):
        self.filename = filename
        self.copy_automaton = XattrsCopiedInBulkAutomaton(self.filename)

    def transition(self, syscall_object):
        self.copy_automaton.transition(syscall_object)

    def is_accepting(self):
        return self.copy_automaton.is_accepting()


class CopyTimestampsDuringCopyChecker:
    """ Detect the case where the destination file's timestamps are not made
        to match the source file's timestamps during a cross-device move.
        1. The source file must be stat()'d
        OR
           The source file must be open()'d and fstat()'d
        2. The destination file must be updated with utimensat()

        Accepting trace: mv_crossdisk_xattrs.strace
        Rejecting trace: mv_crossdisk.strace

        Limitations: Does not check that times are correct, only that a call to
        set them was made
    """
    # TODO: support futimens(), case with just stat()

    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.fstat_src_automaton = OpenAndFstatFileAutomaton(self.src)
        self.update_dst_automaton = OpenAndUtimensatAutomaton(self.dst)

    def transition(self, syscall_object):
        self.fstat_src_automaton.transition(syscall_object)
        self.update_dst_automaton.transition(syscall_object)

    def is_accepting(self):
        return (self.fstat_src_automaton.is_accepting()
                and self.update_dst_automaton.is_accepting())


class MoveDirectoryIntoItselfChecker:
    """ Detect the case where the, through a weird mounting situation, the
        destination is a directory inside the source but on a different device.
        e.g.
        mount /dev/sda1 /mnt/foo/
        mount /dev/sdb1 /mnt/foo/bar
        <move application> /mnt/foo /mnt/foo/bar/foo/

        Some applications make the assumption that because it is a cross-device
        move it is not possible for the the destination to be inside the source.
    """

    def __init__(self):
        raise NotImplementedError('This checker has not been implemented yet')


class OpenAndUtimensatAutomaton:
    # TODO: parse and check for correct times?
    def __init__(self, filename):
        self.filename = filename
        self.states = [{'id': 0,
                        'comment': 'File has not been opened',
                        'accepting': False},
                       {'id': 1,
                        'comment': 'File has been opened',
                        'accepting': False},
                       {'id': 2,
                        'comment': 'File has been utimensat()\'d',
                        'accepting': True}]
        self.current_state = self.states[0]
        self.fd_register = None

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if syscall_object.name == 'open':
                if self.filename in syscall_object.args[0].value:
                    self.fd_register = int(syscall_object.ret[0])
                    self.current_state = self.states[1]
        elif self.current_state['id'] == 1:
            if syscall_object.name == 'utimensat':
                if self.fd_register == int(syscall_object.args[0].value):
                    self.current_state = self.states[2]
                    # It is not possible to transition out of state 2

    def is_accepting(self):
        return self.current_state['accepting']


class OpenAndFstatFileAutomaton:
    def __init__(self, filename):
        self.filename = filename
        self.states = [{'id': 0,
                        'comment': 'File has not been opened',
                        'accepting': False},
                       {'id': 1,
                        'comment': 'File has been opened',
                        'accepting': False},
                       {'id': 2,
                        'comment': 'File has been fstat()\'d',
                        'accepting': True}]
        self.current_state = self.states[0]
        self.fd_register = None

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if syscall_object.name == 'open':
                if self.filename in syscall_object.args[0].value:
                    self.fd_register = int(syscall_object.ret[0])
                    self.current_state = self.states[1]
        elif self.current_state['id'] == 1:
            if syscall_object.name == 'fstat64':
                if self.fd_register == int(syscall_object.args[0].value):
                    self.current_state = self.states[2]
        # It is not possible to transition out of state 2

    def is_accepting(self):
        return self.current_state['accepting']


class DontModifyFileAutomaton:
    def __init__(self, filename):
        self.filename = filename
        self.states = [{'id': 0,
                        'comment': 'File has not been opened',
                        'accepting': True},
                       {'id': 1,
                        'comment': 'File has been opened, not truncated',
                        'accepting': True},
                       {'id': 2,
                        'comment': 'File has been destroyed',
                        'accepting': False}]
        self.current_state = self.states[0]
        self.fd_register = None

    def transition(self, syscall_object):
        # TODO: deal with applications that unlink the file rather than truncate
        if self.current_state['id'] == 0:
            if 'open' in syscall_object.name:
                if self.filename in syscall_object.args[0].value:
                    self.fd_register = int(syscall_object.ret[0])
                    if self._bad_flags(syscall_object.args[1].value):
                        self.current_state = self.states[2]
            elif 'write' in syscall_object.name:
                if self.fd_register == syscall_object.args[0].value:
                    self.current_state = self.states[2]


    def _bad_flags(self, flags):
        append = True if 'O_APPEND' in flags else False
        trunc = True if 'O_TRUNC' in flags else False
        if append and trunc:
            raise NotImplementedError('Weird flag combination %s', flags)
        elif not append:
            return True
        else:
            return False


    def is_accepting(self):
        return self.current_state['accepting']


# Accepts traces where an attempt to rename() the target filename returns
# EXDEV.
# NOTE: some applications specify cross disk move by user input so this
# automaton is not useful in all situations (e.g. mmv)
class RenameEXDEVAutomaton:
    def __init__(self, filename):
        self.filename = filename
        self.states = [{'id': 0,
                        'comment': 'rename has not been attempted on {} yet'
                                   .format(self.filename),
                        'accepting': False},
                       {'id': 1,
                        'comment': 'Got rename that failed with EXDEV',
                        'accepting': True}]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if syscall_object.name == 'rename':
                if self.filename in syscall_object.args[0].value:
                    if syscall_object.ret[1] == 'EXDEV':
                        self.current_state = self.states[1]
        else:
            # There is no way to exit state 1
            pass

    def is_accepting(self):
        return self.current_state['accepting']


# Rejects traces where /dev/urandom is opened and read from as part of a copy
# process. How do we know this is what the program is doing? For example,
# a program could simply be getting some random data from /dev/urandom.
# Likely incomplete handling of some system call orderings.

class UrandomReadDuringCopyAutomaton:
    def __init__(self):
        self.states = [{'id': 0,
                        'comment': '/dev/urandom has not been opened yet',
                        'accepting': True},
                       {'id': 1,
                        'comment': '/dev/urandom is open but has not been '
                                   'read from yet',
                        'accepting': True},
                       {'id': 2,
                        'comment': '/dev/urandom is has been read from',
                        'accepting': True},
                       {'id': 3,
                        'comment': 'the data has been written to dest file',
                        'accepting': False}]
        self.current_state = self.states[0]
        self.data_register = None
        self.urandom_fd = None

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if 'open' in syscall_object.name:
                if '/dev/urandom' in syscall_object.args[0].value:
                    self.current_state = self.states[1]
                    self.urandom_fd = int(syscall_object.ret[0])
        if self.current_state['id'] == 1:
            if 'read' in syscall_object.name:
                if syscall_object.args[0].value == self.urandom_fd:
                    # TODO: track data being read here to see if it is
                    # written back out verbatim to another file rather than
                    # just handling one read and one write
                    self.data_register = syscall_object.args[1].value
                    self.current_state = self.states[2]
        if self.current_state['id'] == 2:
            if 'read' in syscall_object.name:
                if syscall_object.args[0].value == self.urandom_fd:
                    self.data_register = syscall_object.args[1].value
            if 'write' in syscall_object.name:
                if self.data_register in syscall_object.args[1].value:
                    self.current_state = self.states[3]
        if self.current_state['id'] == 3:
            # It is not possible to leave this state
            pass

    def is_accepting(self):
        return self.current_state['accepting']


# Accepts traces where every xattr that was read from the source file is
# applied to the destination file. Will fail on some orderings
class XattrsCopiedInBulkAutomaton:
    def __init__(self, filename):
        self.filename = filename
        self.states = [{'id': 0,
                        'comment': '{} has not been opened yet'
                                   .format(self.filename),
                        'accepting': False},
                       {'id': 1,
                        'comment': 'Reading attributes',
                        'accepting': False},
                       {'id': 2,
                        'comment': 'Writing attributes',
                        'accepting': False},
                       {'id': 3,
                        'comment': 'All attributes written',
                        'accepting': True}]
        self.current_state = self.states[0]
        self.fd_register = None
        self.attrs = []

    # Needs to take into account failed calls
    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if syscall_object.name == 'open':
                if self.filename in syscall_object.args[0].value:
                    self.fd_register = int(syscall_object.ret[0])
                    self.current_state = self.states[1]
        elif self.current_state['id'] == 1:
            if 'fgetxattr' in syscall_object.name:
                if self.fd_register == int(syscall_object.args[0].value) \
                   and syscall_object.args[2].value != '0x0':
                    self.attrs += [syscall_object.args[1].value]
            if 'fsetxattr' in syscall_object.name:
                if syscall_object.args[1].value in self.attrs:
                    self.attrs.remove(syscall_object.args[1].value)
                self.current_state = self.states[2]
        elif self.current_state['id'] == 2:
            if 'fsetxattr' in syscall_object.name:
                if syscall_object.args[1].value in self.attrs:
                    self.attrs.remove(syscall_object.args[1].value)
                if len(self.attrs) == 0:
                    self.current_state = self.states[3]
        elif self.current_state['id'] == 3:
            # It is not possible to leave this state
            pass

    def is_accepting(self):
        return self.current_state['accepting']


class AtLeastOnceWithArgAutomaton:
    def __init__(self, name, arg, pos):
        self.name = name
        self.arg = arg
        self.pos = pos
        self.states = [{'id': 0,
                        'comment': '{} not yet called with {} in position {}'
                                   .format(self.name, self.arg, self.pos),
                        'accepting': False},
                       {'id': 1,
                        'comment': '{} has been called with {} in position {}'
                                   .format(self.name, self.arg, self.pos),
                        'accepting': True}]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if self.name in syscall_object.name \
                    and self.arg in syscall_object.args[self.pos].value:
                self.current_state = self.states[1]

    def is_accepting(self):
        return self.current_state['accepting']


class StatOpenFstatAutomaton:
    def __init__(self, filename):
        self.filename = filename
        self.fd_register = None
        self.states = [{'id': 0,
                        'comment': 'stat64/lstat64 not yet called on {}'
                                   .format(self.filename),
                        'accepting': False},
                       {'id': 1,
                        'comment': 'open not yet called on {}'
                                   .format(self.filename),
                        'accepting': False},
                       {'id': 2,
                        'comment': 'fstat64 not yet called on {}'
                            .format(self.filename),
                        'accepting': False},
                       {'id': 3,
                        'comment': 'expected calls have been made',
                        'accepting': True}]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if syscall_object.name == 'stat64' \
                    or syscall_object.name == 'lstat64':
                if self.filename in syscall_object.args[0].value:
                    self.current_state = self.states[1]
        elif self.current_state['id'] == 1:
            if syscall_object.name == 'open':
                if self.filename in syscall_object.args[0].value:
                    self.fd_register = int(syscall_object.ret[0])
                    self.current_state = self.states[2]
        elif self.current_state['id'] == 2:
            if syscall_object.name == 'fstat64':
                if self.fd_register == int(syscall_object.args[0].value):
                    self.current_state = self.states[3]
        elif self.current_state['id'] == 3:
            # It is not possible to transition out of this state
            pass
        else:
            raise RuntimeError('StatOpenFstatAutomaton for {} tried to '
                               'transition with an illegal current state'
                               .format(self.filename))

    def is_accepting(self):
        return self.current_state['accepting']


class SocketConnectedAndReadChecker:
    def __init__(self, addr, port, data_length):
        self.addr = addr
        self.port = port
        self.data_length = data_length
        self.data_length_register = 0
        self.sockfd_register = 0
        self.states = [{'id': 0,
                        'comment': 'socket not yet connected',
                        'accepting': False},
                       {'id': 1,
                        'comment': 'reading data',
                        'accepting': False},
                       {'id': 2,
                        'comment': 'all data read',
                        'accepting': True}]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if 'connect' in syscall_object.name:
                if 'INET' in str(syscall_object.args[1].value[0]):
                    print(syscall_object.args[1].value[2].value)
                    print(type(syscall_object.args[1].value[2].value))
                    print(syscall_object.args[1].value[1].value)
                    print(type(syscall_object.args[1].value[1].value))
                    print(self.addr in str(syscall_object.args[1].value[2].value))
                    print(self.addr in str(syscall_object.args[1].value[2].value))
                    if self.addr in str(syscall_object.args[1].value[2].value)\
                      and self.port == syscall_object.args[1].value[1].value:
                        print("in here")
                        self.sockfd_register = int(syscall_object.args[0].value)
                        self.current_state = self.states[1]
        if self.current_state['id'] == 1:
            if 'read' in syscall_object.name:
                if int(syscall_object.args[0].value) == self.sockfd_register:
                    self.data_length_register += int(syscall_object.ret[0])
                if self.data_length_register >= self.data_length:
                    self.current_state = self.states[2]
        if self.current_state['id'] == 2:
            # Cannot leave this state
            pass

    def is_accepting(self):
        print(self.current_state['id'])
        print(self.data_length_register)
        return self.current_state['accepting']


class DontReadFileAfterStatChecker:
    def __init__(self, filename):
        self.filename = filename
        self.states = [{'id': 0,
                        'comment': 'file has not been stat()\'d',
                        'accepting': True},
                       {'id': 1,
                        'comment': 'file has not been opened',
                        'accepting': True},
                       {'id': 2,
                        'comment': 'file has not been read',
                        'accepting': True},
                       {'id': 3,
                        'comment': 'file has been read',
                        'accepting': False}]
        self.current_state = self.states[0]
        self.fd_register = 0

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if 'stat64' in syscall_object.name:
                if self.filename in syscall_object.args[0].value:
                    self.current_state = self.states[1]
        if self.current_state['id'] == 1:
            if 'open' in syscall_object.name:
                if self.filename in syscall_object.args[0].value:
                    self.fd_register = int(syscall_object.ret[0])
                    self.current_state = self.states[2]
        if self.current_state['id'] == 2:
            if 'read' in syscall_object.name:
                if self.fd_register == syscall_object.args[0].value:
                    self.current_state = self.states[3]
        if self.current_state['id'] == 3:
            # cannot leave this state
            pass

    def is_accepting(self):
        return self.current_state['accepting']
