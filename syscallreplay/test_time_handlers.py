
"""
<Program Name>
  syscallreplay

<Purpose>
  Provide functions necessary for examining posix-omni-parser provided system
  call objects and writing them into the memory of a process using some
  interface.  Right now this interface is uses ptrace and is provided by the
  syscallreplay CPython extension.

"""


import unittest
import mock
import bunch

import syscallreplay.time_handlers


class TestSyscallReturnSuccessHandler(unittest.TestCase):


  @mock.patch('syscallreplay.util.noop_current_syscall')
  @mock.patch('syscallreplay.time_handlers.util.cint')
  @mock.patch('syscallreplay.util.apply_return_conditions')
  @mock.patch('logging.debug')
  def test_gettimeofday_no_labels(self, mock_log, mock_apply, mock_cint, mock_noop):
    """ Ensure we correctly extract data from gettimeofday() result 
    structure when it DOESN'T have structure field labels.

    """

    mock_cint.EBX = 5
    mock_cint.peek_register_unsigned = mock.Mock(return_value=666)
    mock_populate_timeval_structure = mock.Mock()

    syscall_id = 4
    syscall_object = bunch.Bunch()
    syscall_object.args = [None, None, None]
    arg0_obj = bunch.Bunch()
    arg0_obj.value = '{11223344, '
    arg1_obj = bunch.Bunch()
    arg1_obj.value = '55667788}'
    arg2_obj = bunch.Bunch()
    arg2_obj.value = 'NULL'
    syscall_object.args[0] = arg0_obj
    syscall_object.args[1] = arg1_obj
    syscall_object.args[2] = arg2_obj
    syscall_object.ret = (0,)
    pid = 555
    addr = 666
    #  We don't want to hard code in the debug message here in case it
    #  changes
    syscallreplay.time_handlers.gettimeofday_entry_handler(syscall_id, syscall_object, pid)
    mock_log.assert_called()
    mock_noop.assert_called_with(pid)
    mock_cint.peek_register_unsigned.assert_called_with(pid, mock_cint.EBX)
    mock_cint.populate_timeval_structure.assert_called_with(pid, addr, int(11223344), int(55667788))
    mock_apply.assert_called_with(pid, syscall_object)



  @mock.patch('syscallreplay.util.noop_current_syscall')
  @mock.patch('syscallreplay.time_handlers.util.cint')
  @mock.patch('syscallreplay.util.apply_return_conditions')
  @mock.patch('logging.debug')
  def test_gettimeofday_with_labels(self, mock_log, mock_apply, mock_cint, mock_noop):
    """ Ensure we correctly extract data from gettimeofday() result 
    structure when it has structure field labels.

    """

    mock_cint.EBX = 5
    mock_cint.peek_register_unsigned = mock.Mock(return_value=666)
    mock_populate_timeval_structure = mock.Mock()

    syscall_id = 4
    syscall_object = bunch.Bunch()
    syscall_object.args = [None, None, None]
    arg0_obj = bunch.Bunch()
    arg0_obj.value = '{tv_sec=11223344, '
    arg1_obj = bunch.Bunch()
    arg1_obj.value = 'tv_usec=55667788}'
    arg2_obj = bunch.Bunch()
    arg2_obj.value = 'NULL'
    syscall_object.args[0] = arg0_obj
    syscall_object.args[1] = arg1_obj
    syscall_object.args[2] = arg2_obj
    syscall_object.ret = (0,)
    pid = 555
    addr = 666
    #  We don't want to hard code in the debug message here in case it
    #  changes
    syscallreplay.time_handlers.gettimeofday_entry_handler(syscall_id, syscall_object, pid)
    mock_log.assert_called()
    mock_noop.assert_called_with(pid)
    mock_cint.peek_register_unsigned.assert_called_with(pid, mock_cint.EBX)
    mock_cint.populate_timeval_structure.assert_called_with(pid, addr, int(11223344), int(55667788))
    mock_apply.assert_called_with(pid, syscall_object)



  @mock.patch('syscallreplay.util.noop_current_syscall')
  @mock.patch('syscallreplay.time_handlers.util.cint')
  @mock.patch('syscallreplay.util.apply_return_conditions')
  @mock.patch('logging.debug')
  def test_gettimeofday_failed_call(self, mock_log, mock_apply, mock_cint, mock_noop):
    """ Ensure we raise not implemented error when we get a call with a
    return value indicating failure (-1)

    """

    mock_cint.EBX = 5
    mock_cint.peek_register_unsigned = mock.Mock(return_value=666)
    mock_populate_timeval_structure = mock.Mock()

    syscall_id = 4
    syscall_object = bunch.Bunch()
    syscall_object.args = [None, None, None]
    arg0_obj = bunch.Bunch()
    arg0_obj.value = '{tv_sec=11223344, '
    arg1_obj = bunch.Bunch()
    arg1_obj.value = 'tv_usec=55667788}'
    arg2_obj = bunch.Bunch()
    arg2_obj.value = 'NULL'
    syscall_object.args[0] = arg0_obj
    syscall_object.args[1] = arg1_obj
    syscall_object.args[2] = arg2_obj
    syscall_object.ret = (-1,)
    pid = 555
    #  We don't want to hard code in the debug message here in case it
    #  changes
    with self.assertRaises(NotImplementedError):
      syscallreplay.time_handlers.gettimeofday_entry_handler(syscall_id, syscall_object, pid)
    mock_log.assert_called()
    mock_noop.assert_not_called()
    mock_cint.peek_register_unsigned.assert_not_called()
    mock_cint.populate_timeval_structure.assert_not_called()
    mock_apply.assert_not_called()



  @mock.patch('syscallreplay.util.noop_current_syscall')
  @mock.patch('syscallreplay.time_handlers.util.cint')
  @mock.patch('syscallreplay.util.apply_return_conditions')
  @mock.patch('logging.debug')
  def test_gettimeofday_non_null_timezone_structure(self, mock_log, mock_apply, mock_cint, mock_noop):
    """ Ensure we raise not implemented error when we get a call with a
    non-null timezone structure.

    """

    mock_cint.EBX = 5
    mock_cint.peek_register_unsigned = mock.Mock(return_value=666)
    mock_populate_timeval_structure = mock.Mock()

    syscall_id = 4
    syscall_object = bunch.Bunch()
    syscall_object.args = [None, None, None]
    arg0_obj = bunch.Bunch()
    arg0_obj.value = '{tv_sec=11223344, '
    arg1_obj = bunch.Bunch()
    arg1_obj.value = 'tv_usec=55667788}'
    arg2_obj = bunch.Bunch()
    arg2_obj.value = '{Some Timezone Stuff}'
    syscall_object.args[0] = arg0_obj
    syscall_object.args[1] = arg1_obj
    syscall_object.args[2] = arg2_obj
    syscall_object.ret = (0,)
    pid = 555
    #  We don't want to hard code in the debug message here in case it
    #  changes
    with self.assertRaises(NotImplementedError):
      syscallreplay.time_handlers.gettimeofday_entry_handler(syscall_id, syscall_object, pid)
    mock_log.assert_called()
    mock_noop.assert_not_called()
    mock_cint.peek_register_unsigned.assert_not_called()
    mock_cint.populate_timeval_structure.assert_not_called()
    mock_apply.assert_not_called()
