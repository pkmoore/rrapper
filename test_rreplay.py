#! /usr/bin/env python2

""" Tests for rreplay.py
"""

import unittest
import mock


from rreplay import get_configuration
from rreplay import execute_rr
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

#pylint: disable=too-many-arguments, line-too-long
class TestProcessMessages(unittest.TestCase):
    """ Test processing messages from pipe
    """

    @mock.patch('rreplay.get_message')
    @mock.patch('syscallreplay.util.process_is_alive')
    @mock.patch('__builtin__.open')
    @mock.patch('json.load')
    @mock.patch('json.dump')
    @mock.patch('subprocess.Popen')
    def test_process_messages(self, mock_popen, mock_dump, mock_load, mock_open, mock_process_is_alive, mock_get_message):
        """ Test to see if process_messages receives messages and passes to inject.py
        """
        subjects = []

        process_messages(subjects)
        mock_get_message.assert_called_with('rrdump_proc.pipe')
#pylint: enable=too-many-arguments,line-too-long
