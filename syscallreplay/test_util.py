"""
<Program Name>
  test_util

<Purpose>
  Provide tests for the functions collected in util.py

"""


import unittest
import mock
import bunch

import syscallreplay.util


class TestProcessIsAlive(unittest.TestCase):

  @mock.patch('os.kill')
  def test_process_does_not_exist(self, mock_kill):
    """Ensure returns False when process does not exist
    <Purpose>
      Ensure this function returns False when os.kill() indicates that the
      specified process does not exist by raising an OSError.

    """

    mock_kill.side_effect = OSError('Process does not exist')

    pid = 555
    signal_number = 0
    self.assertEqual(syscallreplay.util.process_is_alive(pid), False)
    mock_kill.assert_called_with(pid, signal_number)


  @mock.patch('os.kill')
  def test_process_exists(self, mock_kill):
    """Ensure returns True when process does not exist
    <Purpose>
      Ensure this function returns True when os.kill() indicates that the
      specified process is alive (i.e. kill(0) succeeds).

    """

    pid = 555
    signal_number = 0
    self.assertEqual(syscallreplay.util.process_is_alive(pid), True)
    mock_kill.assert_called_with(pid, signal_number)





class TestStringTimeToInt(unittest.TestCase):

  @mock.patch('logging.debug')
  def test_zero_strtime(self, mock_log):
    """Ensure '0' strtime returns 0
    <Purpose>
      Ensure that a string time of 0 passed in returns the int 0

    """
    strtime = '0'
    self.assertEqual(syscallreplay.util.string_time_to_int(strtime), 0)
    mock_log.assert_called()


  @mock.patch('logging.debug')
  @mock.patch('__builtin__.int')
  @mock.patch('time.mktime')
  @mock.patch('time.strptime')
  def test_nonzero_strtime(self, mock_strptime, mock_mktime, mock_int, mock_log):
    """Ensure correct int time if strtime valid non-'0'
    <Purpose>
      Ensure that a correct int time value is calculated when a non-'0'
      strtime is provided.

    """
    strtime = '2001/01/01-01:01:01'
    strptime_format = '%Y/%m/%d-%H:%M:%S'
    strptime_return_value = mock.Mock(tm_year=2001,
                                      tm_mon=1,
                                      tm_mday=1,
                                      tm_hour=1,
                                      tm_min=1,
                                      tm_sec=1,
                                      tm_wday=0,
                                      tm_yday=1,
                                      tm_isdst=1)
    mktime_return_value = 97833961.0
    int_return_value = 97833961

    mock_strptime.return_value = strptime_return_value
    mock_mktime.return_value = mktime_return_value
    mock_int.return_value = int_return_value

    self.assertEqual(syscallreplay.util.string_time_to_int(strtime), int_return_value)

    mock_log.assert_called()
    mock_strptime.assert_called_with(strtime, strptime_format)
    mock_mktime.assert_called_with(strptime_return_value)
    mock_int.assert_called_with(mktime_return_value)





class TestStopForDebug(unittest.TestCase):

  @mock.patch('logging.debug')
  @mock.patch('signal.SIGSTOP')
  @mock.patch('os.kill')
  @mock.patch('syscallreplay.util.cint')
  def TestWithPid(self, mock_syscallreplay, mock_kill, mock_signal, mock_log):
    """Ensure pausing for debug works correclty when passed a pid
    <Purpose>
      Ensure pausing for debug works correctly
    """
    pid = 555

    mock_syscallreplay.detach = mock.Mock()

    self.assertRaises(syscallreplay.util.ReplayDeltaError, syscallreplay.util.stop_for_debug, pid)

    mock_log.assert_called()
    mock_kill.assert_called_with(pid, mock_signal)
    mock_syscallreplay.detach.assert_called_with(pid)





class TestNoopCurrentSyscall(unittest.TestCase):

  @mock.patch('logging.debug')
  @mock.patch('syscallreplay.util.next_syscall')
  @mock.patch('syscallreplay.util.cint')
  def test_with_successful_noop(self, mock_syscallreplay, mock_next, mock_log):
    """Test for correct noop with valid pid
    <Purpose>
      Ensure a correct noop process happens when passed a valid pid

    """
    pid = 555
    getpid_syscallno = 20
    ptrace_syscall_signalno = 0

    mock_syscallreplay.poke_register = mock.Mock()
    mock_syscallreplay.ORIG_EAX = mock.Mock()
    mock_syscallreplay.syscall = mock.Mock()
    mock_syscallreplay.peek_register = mock.Mock(return_value=getpid_syscallno)
    mock_syscallreplay.entering_syscall = True

    syscallreplay.util.noop_current_syscall(pid)

    mock_log.assert_called()
    mock_syscallreplay.poke_register.assert_called_with(pid, mock_syscallreplay.ORIG_EAX, getpid_syscallno)
    mock_syscallreplay.syscall.assert_called_with(pid, ptrace_syscall_signalno)
    mock_next.assert_called()
    mock_syscallreplay.peek_register(pid, mock_syscallreplay.ORIG_EAX)
    self.assertEqual(mock_syscallreplay.entering_syscall, False)


  @mock.patch('logging.debug')
  @mock.patch('syscallreplay.util.next_syscall')
  @mock.patch('syscallreplay.util.cint')
  def test_for_exception_when_noop_fails(self, mock_syscallreplay, mock_next, mock_log):
    """Make sure an exception is raised when nooping doesn't go as expected
    <Purpose>
      Make sure an exception is raised when nooping doesn't go as expected

    """
    pid = 555
    getpid_syscallno = 20
    bad_syscallno = -1
    ptrace_syscall_signalno = 0

    mock_syscallreplay.poke_register = mock.Mock()
    mock_syscallreplay.ORIG_EAX = mock.Mock()
    mock_syscallreplay.syscall = mock.Mock()
    mock_syscallreplay.peek_register = mock.Mock(return_value=bad_syscallno)
    mock_syscallreplay.entering_syscall = True

    self.assertRaises(Exception, syscallreplay.util.noop_current_syscall, pid)

    mock_log.assert_called()
    mock_syscallreplay.poke_register.assert_called_with(pid, mock_syscallreplay.ORIG_EAX, getpid_syscallno)
    mock_syscallreplay.syscall.assert_called_with(pid, ptrace_syscall_signalno)
    mock_next.assert_called()
    mock_syscallreplay.peek_register(pid, mock_syscallreplay.ORIG_EAX)
    self.assertEqual(mock_syscallreplay.entering_syscall, True)





class TestNextSyscall(unittest.TestCase):

  @mock.patch('os.wait', return_value=[None, False])
  @mock.patch('os.WIFEXITED', return_value=False)
  def test_have_next_systemcall(self, mock_exited, mock_wait):
    """Make sure True is returned when there is a next system call
    <Purpose>
      Make sure True is returned when there is a next system call.  We know this
      is the case when os.WIFEXITED's returned status indicates the process has
      NOT exited.

    """

    self.assertEqual(syscallreplay.util.next_syscall(), True)

    mock_wait.assert_called()
    mock_exited.assert_called_with(False)


  @mock.patch('os.wait', return_value=[None, True])
  @mock.patch('os.WIFEXITED', return_value=True)
  def test_have_next_systemcall(self, mock_exited, mock_wait):
    """Make sure False is returned when the process has exited
    <Purpose>
      Make sure False is returned when the processes has exited.

    """

    self.assertEqual(syscallreplay.util.next_syscall(), False)

    mock_wait.assert_called()
    mock_exited.assert_called_with(True)





class TestExtractSocketcallParameters(unittest.TestCase):

  @mock.patch('logging.debug')
  @mock.patch('syscallreplay.util.cint')
  def test_extract_parameters(self, mock_syscallreplay, mock_logging):
    """Ensure parameters are extracted correctly
    <Purpose>
      Make sure parameters are correctly extracted


    """
    pid = 555
    num_params = 6
    address = 0xbf000000
    fake_params = [1, 2, 3, 0xa, 0xb, 0xc]

    mock_syscallreplay.peek_address = mock.Mock(side_effect=iter(fake_params))
    peek_calls = [mock.call(555, address),
                  mock.call(555, address+4),
                  mock.call(555, address+8),
                  mock.call(555, address+12),
                  mock.call(555, address+16),
                  mock.call(555, address+20)]

    self.assertEqual(syscallreplay.util.extract_socketcall_parameters(pid, address, num_params), fake_params)
    mock_syscallreplay.peek_address.assert_has_calls(peek_calls)
    mock_logging.assert_called()





class TestValidateSyscall(unittest.TestCase):

  def test_matching_id_and_object(self):
    """Ensure a matching id and object doesn't raise
    <Purpose>
      Make sure a system call id that matches syscall_object.name doesn't raise

    """
    syscall_id = 4
    syscall_object = bunch.Bunch()
    syscall_object.name = 'write'

    syscallreplay.util.validate_syscall(syscall_id, syscall_object)


  def test_non_matching_id_and_object(self):
    """Ensure non-matching id and object DO raise
    <Purpose>
      Make sure a system call id that does not match syscall_object.name raises

    """

    syscall_id = 5
    syscall_object = bunch.Bunch()
    syscall_object.name = 'write'

    self.assertRaises(syscallreplay.util.ReplayDeltaError,
                      syscallreplay.util.validate_syscall, syscall_id, syscall_object)





class TestValidateSubcall(unittest.TestCase):

  def test_matching_id_and_object(self):
    """Ensure matching id and object doesn't raise
    <Purpose>
      Make sure socket subcall id that matches syscall_object.name doesn't raise

    """
    subcall_id = 1
    syscall_object = bunch.Bunch()
    syscall_object.name = 'socket'

    syscallreplay.util.validate_subcall(subcall_id, syscall_object)

  def test_non_matching_id_and_object(self):
    """Ensure non-matching id and object doesn't raise
    <Purpose>
      Make sure socket subcall id that doesn't match syscall_object.name raises

    """
    subcall_id = 9
    syscall_object = bunch.Bunch()
    syscall_object.name = 'socket'

    self.assertRaises(syscallreplay.util.ReplayDeltaError,
                      syscallreplay.util.validate_subcall, subcall_id, syscall_object)
