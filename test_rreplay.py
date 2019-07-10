#! /usr/bin/env python2

""" Tests for rreplay.py
"""

import unittest
import mock
import bunch


from rreplay import get_configuration
from rreplay import execute_rr
from rreplay import wait_on_handles
from rreplay import process_messages

# pylint: disable=no-self-use


class TestGetConfiguration(unittest.TestCase):
    """ Test get_configuration helper function
    """

    @mock.patch('ConfigParser.SafeConfigParser.read')
    @mock.patch('rreplay.logger')
    def test_get_configuration(self, mock_logger, mock_config_read):
        """ Ensure that the configuration file is opened and parsed
        """

        config_file = "test/flask_request.ini"
        try:
            get_configuration(config_file)
        except IOError:
            pass

        mock_logger.debug.assert_called()
        mock_config_read.assert_called_with(config_file)






class TestExecuteRR(unittest.TestCase):
    """ Test execute_rr helper function
    """

    @mock.patch('os.environ.copy')
    @mock.patch('rreplay.logger')
    @mock.patch('__builtin__.open')
    @mock.patch('subprocess.Popen')
    def test_execute_rr(self, mock_popen, mock_open, mock_logger, mock_environ_copy):
        """ Test to ensure that subjects are parsed for rr command executin
        """

        subjects = [{'rec_pid': '123', 'event': '123'}]

        execute_rr("test-1", subjects)
        mock_environ_copy.assert_called()
        mock_logger.debug.assert_called()
        # check if proc.out is opened for writing output
        mock_open.assert_called_with('proc.out', 'w')
        mock_popen.assert_called()





class TestProcessMessages(unittest.TestCase):
  """Test process_messages
  """

  @mock.patch('rreplay.get_message', return_value='{bad}')
  def test_invalid_json_message(self, mock_get_message):
    """A badly formatted json message should result in a ValueError
    """

    subjects = [{'rec_pid': '123', 'event': '123'}]
    self.assertRaises(ValueError, process_messages, subjects)



  @mock.patch('rreplay.get_message', return_value='''{
                                                     "inject": "true",
                                                     "event": "140",
                                                     "pid": "120",
                                                     "rec_pid": "1100",
                                                     "brks": []
                                                   }''')
  @mock.patch('rreplay.logger')
  @mock.patch('rreplay.json.dump')
  @mock.patch('rreplay.util.process_is_alive', return_value=True)
  @mock.patch('rreplay.open')
  @mock.patch('rreplay.json.load', return_value={"rec_pid": "1849",
                                                 "trace_file": "/home/preston/.crashsim/mytest32/trace_snip0.strace",
                                                 "injected_state_file": "140_FutureTimeMutator()_state.json",
                                                 "mutator": "FutureTimeMutator()",
                                                 "trace_start": "0",
                                                 "trace_end": "5",
                                                 "event": "140",
                                                 "other_procs": []})
  @mock.patch('rreplay.subprocess.Popen', return_value=bunch.Bunch)
  @mock.patch('rreplay.os.unlink')
  def test_good_json_message_do_inject(self,
                                       mock_unlink,
                                       mock_popen,
                                       mock_json_load,
                                       mock_open,
                                       mock_process_is_alive,
                                       mock_json_dump,
                                       mock_logger,
                                       mock_get_message):
    """A well formatted json message with inject == true should be handled
    """

    subjects = [{'mutator': 'NullMutator(70)',
                 'rec_pid': '1100',
                 'event': '140',
                 'injected_state_file': '140_NullMutator(70)_state.json'}]
    process_messages(subjects)
    mock_process_is_alive.assert_called_with('120')
    # make sure we open the eventwise config file
    mock_open.assert_has_calls([mock.call('140_NullMutator(70)_state.json', 'r')])
    mock_json_load.assert_called()
    # make sure we dump out the pid unique config file after we have
    # generated it
    mock_json_dump.assert_called()
    # make sure we spin off a subprocess with the correct parameters
    # based on the configured state
    mock_popen.assert_called_with(['inject',
                                   '--verbosity=40',
                                   '120_140_NullMutator(70)_state.json'])
    mock_unlink.assert_called_with('140_NullMutator(70)_state.json')


  @mock.patch('rreplay.get_message', return_value='''{
                                                     "inject": "false",
                                                     "event": "140",
                                                     "pid": "120",
                                                     "rec_pid": "1100",
                                                     "brks": []
                                                   }''')
  @mock.patch('rreplay.logger')
  @mock.patch('rreplay.json.dump')
  @mock.patch('rreplay.util.process_is_alive', return_value=True)
  @mock.patch('rreplay.open')
  @mock.patch('rreplay.json.load', return_value={"rec_pid": "1849",
                                                 "trace_file": "/home/preston/.crashsim/mytest32/trace_snip0.strace",
                                                 "injected_state_file": "140_FutureTimeMutator()_state.json",
                                                 "mutator": "FutureTimeMutator()",
                                                 "trace_start": "0",
                                                 "trace_end": "5",
                                                 "event": "140",
                                                 "other_procs": []})
  @mock.patch('rreplay.subprocess.Popen', return_value=bunch.Bunch)
  def test_good_json_message_dont_inject(self,
                                         mock_popen,
                                         mock_json_load,
                                         mock_open,
                                         mock_process_is_alive,
                                         mock_json_dump,
                                         mock_logger,
                                         mock_get_message):
    """A well formatted json message with inject == false should not
       spawn a subprocess
    """

    subjects = [{'mutator': 'NullMutator(70)',
                 'rec_pid': '1100',
                 'event': '140',
                 'injected_state_file': '140_NullMutator(70)_state.json',
                 'other_procs': []}]
    process_messages(subjects)
    mock_process_is_alive.assert_called_with('120')
    # make sure we open the eventwise config file
    mock_open.not_called()
    mock_json_load.assert_not_called()
    # make sure we dump out the pid unique config file after we have
    # generated it
    mock_json_dump.assert_not_called()
    # make sure we spin off a subprocess with the correct parameters
    # based on the configured state
    self.assertEqual(subjects[0]['other_procs'], ['120'])


  @mock.patch('rreplay.get_message', return_value='''{
                                                     "inject": "false",
                                                     "event": "140",
                                                     "pid": "120",
                                                     "rec_pid": "1100",
                                                     "brks": []
                                                   }''')
  @mock.patch('rreplay.logger')
  @mock.patch('rreplay.json.dump')
  @mock.patch('rreplay.util.process_is_alive', return_value=True)
  @mock.patch('rreplay.open')
  @mock.patch('rreplay.json.load', return_value={"rec_pid": "1849",
                                                 "trace_file": "/home/preston/.crashsim/mytest32/trace_snip0.strace",
                                                 "injected_state_file": "140_FutureTimeMutator()_state.json",
                                                 "mutator": "FutureTimeMutator()",
                                                 "trace_start": "0",
                                                 "trace_end": "5",
                                                 "event": "140",
                                                 "other_procs": []})
  @mock.patch('rreplay.subprocess.Popen', return_value=bunch.Bunch)
  def test_message_is_for_past_event(self,
                                     mock_popen,
                                     mock_json_load,
                                     mock_open,
                                     mock_process_is_alive,
                                     mock_json_dump,
                                     mock_logger,
                                     mock_get_message):
    """ We should ignore messages for events in the past
    """
    # This subject expects event 180, but we receive a mock message for event 140
    subjects = [{'mutator': 'NullMutator(70)',
                 'rec_pid': '1100',
                 'event': '180',
                 'injected_state_file': '140_NullMutator(70)_state.json',
                 'other_procs': []}]

    process_messages(subjects)
    mock_get_message.assert_called()
    mock_process_is_alive.assert_called_with('120')
    # make sure we open the eventwise config file
    mock_process_is_alive.assert_called()
    mock_open.not_called()

    # make sure we dump out the pid unique config file after we have
    # generated it
    mock_json_dump.assert_not_called()
    # make sure we spin off a subprocess with the correct parameters
    # based on the configured state


  @mock.patch('rreplay.get_message', return_value='''{
                                                     "inject": "true",
                                                     "event": "180",
                                                     "pid": "120",
                                                     "rec_pid": "1100",
                                                     "brks": []
                                                   }''')
  @mock.patch('rreplay.logger')
  @mock.patch('rreplay.json.dump')
  @mock.patch('rreplay.util.process_is_alive', return_value=True)
  @mock.patch('rreplay.open')
  @mock.patch('rreplay.json.load', return_value={"rec_pid": "1849",
                                                 "trace_file": "/home/preston/.crashsim/mytest32/trace_snip0.strace",
                                                 "injected_state_file": "180_FutureTimeMutator()_state.json",
                                                 "mutator": "FutureTimeMutator()",
                                                 "trace_start": "0",
                                                 "trace_end": "5",
                                                 "event": "180",
                                                 "other_procs": []})
  @mock.patch('rreplay.subprocess.Popen', return_value=bunch.Bunch)
  @mock.patch('rreplay.os.unlink')
  def test_message_is_for_future_event(self,
                                       mock_unlink,
                                       mock_popen,
                                       mock_json_load,
                                       mock_open,
                                       mock_process_is_alive,
                                       mock_json_dump,
                                       mock_logger,
                                       mock_get_message):
    """A message for a future event should cause us to fast foward to it
    """

    subjects = [
        {'mutator': 'NullMutator(70)',
         'rec_pid': '1100',
         'event': '140',
         'injected_state_file': '140_NullMutator(70)_state.json',
         'other_procs': []},
        {'mutator': 'NullMutator(90)',
         'rec_pid': '1100',
         'event': '180',
         'injected_state_file': '180_NullMutator(90)_state.json',
         'other_procs': []}
    ]
    process_messages(subjects)
    mock_process_is_alive.assert_called_with('120')
    # make sure we open the eventwise config file
    mock_open.assert_has_calls([mock.call('180_NullMutator(90)_state.json', 'r')])
    mock_json_load.assert_called()
    # make sure we dump out the pid unique config file after we have
    # generated it
    mock_json_dump.assert_called()
    # make sure we spin off a subprocess with the correct parameters
    # based on the configured state
    mock_popen.assert_called_with(['inject',
                                   '--verbosity=40',
                                   '120_180_NullMutator(90)_state.json'])
    mock_unlink.assert_called_with('180_NullMutator(90)_state.json')


class TestWaitOnHandles(unittest.TestCase):
    """ Test wait_on_handles helper function
    """

    @mock.patch('subprocess.Popen')
    @mock.patch('os.kill')
    @mock.patch('signal.SIGKILL')
    def test_correct_wait_for_subject(self, mock_sigkill, mock_kill, mock_popen):
        """ We should wait on a subject's handle until inject.py completes
        """
        s_handle = mock_popen(['python', 'test.py'])
        s_handle.wait = mock.Mock()
        subjects = [{'handle': s_handle, 'rec_pid': '123', 'event': '123', 'other_procs': [111, 112, 113, 114]}]

        wait_on_handles(subjects)
        s_handle.wait.assert_called_with()



    @mock.patch('subprocess.Popen')
    @mock.patch('os.kill')
    @mock.patch('signal.SIGKILL')
    def test_kill_other_procs(self, mock_sigkill, mock_kill, mock_popen):
        """ We should kill all 'other procs' for a subject we are waiting on
        """
        s_handle = mock_popen(['python', 'test.py'])
        s_handle.wait = mock.Mock()
        subjects = [{'handle': s_handle, 'rec_pid': '123', 'event': '123', 'other_procs': [111, 112, 113, 114]}]

        wait_on_handles(subjects)
        # test os.kill mock on last PID
        mock_kill.assert_has_calls([mock.call(111, mock_sigkill),
                                    mock.call(112, mock_sigkill),
                                    mock.call(113, mock_sigkill),
                                    mock.call(114, mock_sigkill)])
