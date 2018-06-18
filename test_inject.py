#! /usr/bin/env python2

""" Tests for inject.py
"""

import unittest
import mock


from inject import exit_with_status
from inject import apply_mmap_backing_files

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


class ApplyMmapBackingFilesTestCase(unittest.TestCase):
    """Test apply_mmap_backing_files helper function
    """

    @mock.patch('inject.syscallreplay', spec=['injected_state'])
    @mock.patch('inject.parse_backing_files')
    def test_apply_mmap_backing_line(self,
                                     mock_parse_backing_files,
                                     mock_syscallreplay):
        """ Test applying mmap backing file configuration
        """

        mock_syscallreplay.injected_state = {'config':
                                             {'mmap_backing_files': '1:/test'}}
        apply_mmap_backing_files()
        mock_parse_backing_files.assert_called_with('1:/test')

    @mock.patch('inject.syscallreplay', spec=['injected_state'])
    @mock.patch('inject.parse_backing_files')
    def test_apply_mmap_backing_no_line(self,
                                        mock_parse_backing_files,
                                        mock_syscallreplay):
        """ Test not applying backing files when they are not present
        """

        mock_syscallreplay.injected_state = {'config': {}}
        apply_mmap_backing_files()
        mock_parse_backing_files.assert_not_called()
