#! /usr/bin/env python2

""" Tests for inject.py
"""

import unittest
import mock


from inject import exit_with_status

# pylint: disable=no-self-use


class ExitWithStatusTestCase(unittest.TestCase):
    """Test exit_with_status helper function
    """

    @mock.patch('inject._kill_parent_process')
    @mock.patch('traceback.print_exc')
    @mock.patch('sys.exit')
    def test_exit_with_zero_status(self,
                                   mock_exit,
                                   mock_print_exc,
                                   mock__kill_parent_process):
        """ Test correctly exiting with zero status
        """

        pid = 555
        exit_status = 0
        exit_with_status(pid, exit_status)
        mock__kill_parent_process.assert_called_with(pid)
        mock_exit.assert_called_with(exit_status)
        mock_print_exc.assert_not_called()

    @mock.patch('inject._kill_parent_process')
    @mock.patch('traceback.print_exc')
    @mock.patch('sys.exit')
    def test_exit_with_non_zero_status(self,
                                       mock_exit,
                                       mock_print_exc,
                                       mock__kill_parent_process):
        """ Test correctly exiting with non-zero status
        """

        pid = 555
        exit_status = -1
        exit_with_status(pid, exit_status)
        mock__kill_parent_process.assert_called_with(pid)
        mock_exit.assert_called_with(exit_status)
        mock_print_exc.assert_called()
