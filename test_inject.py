#! /usr/bin/env python2

""" Tests for inject.py
"""

import unittest
import mock
from bunch import Bunch

from syscallreplay.util import ReplayDeltaError
from syscallreplay import util
import syscallreplay

from inject import exit_with_status
from inject import apply_mmap_backing_files
from inject import consume_configuration
from inject import parse_backing_files
from inject import debug_handle_syscall
from inject import handle_syscall

# pylint: disable=no-self-use


class TestExitWithStatusTestCase(unittest.TestCase):
    """Test exit_with_status helper function
    """

    @mock.patch('re.findall')
    @mock.patch('inject._kill_parent_process')
    @mock.patch('traceback.print_exc')
    @mock.patch('sys.exit')
    def test_exit_with_zero_status(self,
                                   mock_exit,
                                   mock_print_exc,
                                   mock__kill_parent_process,
                                   mock_re_findall):
        """ Test correctly exiting with zero status
        """

        pid = 555
        exit_status = 0
        event = 140
        index = 26
        mutator = '<src.mutator.Null.NullMutator instance at 0xb736808c>'
        exit_with_status(pid, exit_status, mutator, event, index)
        mock__kill_parent_process.assert_called_with(pid)
        mock_exit.assert_called_with(exit_status)
        mock_print_exc.assert_not_called()
        mock_re_findall.assert_called_with(r'src.mutator.\w+.(\w+)', mutator)

    @mock.patch('re.findall')
    @mock.patch('inject._kill_parent_process')
    @mock.patch('traceback.print_exc')
    @mock.patch('sys.exit')
    def test_exit_with_non_zero_status(self,
                                       mock_exit,
                                       mock_print_exc,
                                       mock__kill_parent_process,
                                       mock_re_findall):
        """ Test correctly exiting with non-zero status
        """

        pid = 555
        exit_status = -1
        event = 150
        index = 26
        mutator = '<src.mutator.Null.NullMutator instance at 0xb736808c>'
        exit_with_status(pid, exit_status, mutator, event, index)
        mock__kill_parent_process.assert_called_with(pid)
        mock_exit.assert_called_with(exit_status)
        mock_print_exc.assert_called()
        mock_re_findall.assert_called_with(r'src.mutator.\w+.(\w+)', mutator)


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

        mock_sr.injected_state = {'mmap_backing_files': '1:/test'}
        apply_mmap_backing_files()
        mock_parse_backing_files.assert_called_with('1:/test')

    @mock.patch('inject.syscallreplay', spec=['injected_state'])
    @mock.patch('inject.parse_backing_files')
    def test_apply_mmap_backing_no_line(self,
                                        mock_parse_backing_files,
                                        mock_syscallreplay):
        """ Test not applying backing files when they are not present
        """

        mock_syscallreplay.injected_state = {}
        apply_mmap_backing_files()
        mock_parse_backing_files.assert_not_called()


class TestConsumeConfiguration(unittest.TestCase):
    """ Test consuming configuration, applying it, and removing the file.
    """

    @mock.patch('__builtin__.open')
    @mock.patch('json.load')
    @mock.patch('os.path.exists', return_value=False)
    @mock.patch('os.remove')
    def test_consume_configuration(self, mock_remove, mock_exists, mock_load, mock_open):
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


class TestHandleSyscall(unittest.TestCase):
    """ Test handle_syscall
    """

    @mock.patch('inject.handle_socketcall')
    @mock.patch('inject.util.validate_syscall')
    def test_handle_syscall_with_syscallid_102(self, mock_validate_syscall, mock_handle_socketcall):
        pid = 555
        syscall_id = 102
        syscall_object = Bunch()
        entering = True
        handle_syscall(pid, syscall_id, syscall_object, entering)
        mock_handle_socketcall.assert_called_with(syscall_id, syscall_object, entering, pid)
        mock_validate_syscall.assert_not_called()


    @mock.patch('inject.handle_socketcall')
    @mock.patch('inject.util.validate_syscall')
    def test_handle_syscall_with_syscallid_not102(self, mock_validate_syscall, mock_handle_socketcall):
        pid = 555
        syscall_id = 91
        syscall_object = Bunch()
        syscall_object.name = 'open'
        entering = True
        handle_syscall(pid, syscall_id, syscall_object, entering)
        mock_handle_socketcall.assert_not_called()
        mock_validate_syscall.assert_called_with(syscall_id, syscall_object)
