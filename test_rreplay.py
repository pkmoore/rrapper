#! /usr/bin/env python2

""" Tests for rreplay.py
"""

import unittest
import mock


from rreplay import get_configuration
from rreplay import execute_rr
from rreplay import wait_on_handles

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
        get_configuration(config_file)
        mock_logger.debug.assert_called()
        mock_config_read.assert_called()


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

#pylint disable=line-too-long
class TestWaitOnHandles(unittest.TestCase):
    """ Test wait_on_handles helper function
    """

    @mock.patch('subprocess.Popen')
    @mock.patch('subprocess.Popen.wait')
    @mock.patch('os.kill')
    @mock.patch('signal.SIGKILL')
    def test_injector_success(self, mock_sigkill, mock_kill, mock_wait, mock_popen):
        """ Test handle wait for subjects successfully
        """
        s_handle = mock_popen(['python', 'test.py'])
        subjects = [{'handle': s_handle, 'rec_pid': '123', 'event': '123', 'other_procs': [111, 112, 113, 114]}]

        wait_on_handles(subjects)
        mock_wait.assert_called_with(subjects[0]['handle'])
        # test os.kill mock on last PID
        mock_kill.assert_called_with(114, mock_sigkill)

    @mock.patch('os.kill')
    @mock.patch('signal.SIGKILL')
    def test_injector_fail(self, mock_sigkill, mock_kill):
        """ Test failed injector on because of no handles
        """
        subjects = [{'rec_pid': '123', 'event': '123', 'other_procs': [111, 112, 113, 114]}]

        wait_on_handles(subjects)
        # test os.kill mock on last PID
        mock_kill.assert_called_with(114, mock_sigkill)
#pylint enable=line-too-long
