#! /usr/bin/env python2

""" Tests for inject.py
"""

import unittest
import mock
from bunch import Bunch

from syscallreplay.util import ReplayDeltaError

from inject import exit_with_status
from inject import apply_mmap_backing_files
from inject import apply_open_fds
from inject import consume_configuration
from inject import parse_backing_files
from inject import debug_handle_syscall

# pylint: disable=no-self-use


class TestExitWithStatusTestCase(unittest.TestCase):
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


class TestApplyMmapBackingFilesTestCase(unittest.TestCase):
    """Test apply_mmap_backing_files helper function
    """

    @mock.patch('inject.syscallreplay', spec=['injected_state'])
    @mock.patch('inject.parse_backing_files')
    def test_apply_mmap_backing_line(self,
                                     mock_parse_backing_files,
                                     mock_sr):
        """ Test applying mmap backing file configuration
        """

        mock_sr.injected_state = {'config': {'mmap_backing_files': '1:/test'}}
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


class TestApplyOpenFds(unittest.TestCase):
    """ Test applying open fds to the correct spot in injected_state
    """

    @mock.patch('inject.syscallreplay', spec=['injected_state'])
    def test_apply_openfds(self, mock_sr):
        """ Make sure open fds are applied correctly
        """

        mock_sr.injected_state = {'open_fds': {'1111': [1]}}
        apply_open_fds('1111')
        self.assertEqual(cmp(mock_sr.injected_state['open_fds'], [1]), 0)


class TestConsumeConfiguration(unittest.TestCase):
    """ Test consuming configuration, applying it, and removing the file.
    """

    @mock.patch('__builtin__.open')
    @mock.patch('json.load')
    @mock.patch('os.remove')
    def test_consume_configuration(self, mock_remove, mock_load, mock_open):
        """ Ensure file is opened with read, loaded as json, and removed
        """
        config_file = 'config.json'
        consume_configuration(config_file)
        mock_open.assert_called_with(config_file, 'r')
        #  Not testing what load was passed as it will be a mock in this case
        mock_load.assert_called()
        mock_remove.assert_called_with(config_file)


class TestParseBackingFiles(unittest.TestCase):
    """ Test parsing mmap backing files into an appropriate dictionary
    """

    def test_parse_valid_backing_files(self):
        """ Make sure we build a correct dictionary for a given line
        """
        files_dict = parse_backing_files('11:/test.txt')
        self.assertEqual(cmp(files_dict, {'11': '/test.txt'}), 0)


class TestDebugHandleSyscall(unittest.TestCase):
    """ Test debug_handle_syscall
    """

    @mock.patch('inject.handle_syscall')
    def test_handle_no_exception(self, mock_handle):
        """ Ensure we call handle_syscall with the appropriate args and don't
        blow up if we don't have an exception.
        """
        pid = 555
        syscall_id = 102
        entering = True
        syscall_object = Bunch()
        debug_handle_syscall(pid, syscall_id, syscall_object, entering)
        mock_handle.assert_called_with(pid,
                                       syscall_id,
                                       syscall_object,
                                       entering)

    @mock.patch('inject.handle_syscall')
    @mock.patch('syscallreplay.file_handlers.open_entry_debug_printer')
    def test_handle_replay_delta_error(self, mock_printer, mock_handle):
        pid = 555
        syscall_id = 5
        entering = True
        syscall_object = Bunch()
        mock_handle.side_effect = ReplayDeltaError('A test error')
        self.assertRaises(ReplayDeltaError,
                          debug_handle_syscall,
                          pid,
                          syscall_id,
                          syscall_object,
                          entering)
        mock_printer.assert_called_with(pid, syscall_id, syscall_object)
