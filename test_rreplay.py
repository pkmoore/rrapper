#! /usr/bin/env python2

""" Tests for rreplay.py
"""

import unittest
import mock


from rreplay import get_configuration
from rreplay import execute_rr
from rreplay import process_messages
from rreplay import wait_on_handles

# pylint: disable=no-self-use


class TestGetConfiguration(unittest.TestCase):
    """ Test get_configuration helper function
    """

    @mock.patch('ConfigParser.SafeConfigParser.read')
    @mock.patch('rreplay.logger')
    def test_get_configuration(self,mock_logger, mock_config_read):
        """ Ensure that file is opened, parsed, and closed
        """ 

        config_file = "config.ini"
        get_configuration(config_file)
        mock_logger.debug.assert_called()
        mock_config_read.assert_called_with(config_file)
    

class TestExecuteRR(unittest.TestCase):
    """ Test the execution of the rr command
    """

    @mock.patch('os.environ.copy')
    @mock.patch('rreplay.logger')
    @mock.patch('__builtin__.open')
    @mock.patch('subprocess.Popen')
    def test_execute_rr(self, mock_popen, mock_open, mock_logger, mock_environ_copy):
       
        subjects = [{'rec_pid': '123', 'event': '123'}]

        execute_rr("test-1", subjects)
        mock_environ_copy.assert_called()
        mock_logger.debug.assert_called()
        mock_open.assert_called_with('proc.out', 'w')
        mock_popen.assert_called()

