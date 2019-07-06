#! /usr/bin/env python2
""" Test the methods provided by the GenericMutator class
"""

from src.mutator.mutator import GenericMutator

import unittest
import mock
import tempfile
from bunch import Bunch


class TestFindSyscallBetweenIndexes(unittest.TestCase):
  def test_fail_on_negative_start_index(self):
    syscalls = Bunch()
    start = -1
    end = 10
    pred_func = lambda x: False
    mutator = GenericMutator()
    self.assertRaises(ValueError,
                      mutator.find_syscall_between_indexes, syscalls,
                                                            start,
                                                            end,
                                                            pred_func)


  def test_fail_on_negative_end_index(self):
    syscalls = Bunch()
    start = 0
    end = -1
    pred_func = lambda x: False
    mutator = GenericMutator()
    self.assertRaises(ValueError,
                      mutator.find_syscall_between_indexes, syscalls,
                                                            start,
                                                            end,
                                                            pred_func)


  def test_fail_on_start_equals_end(self):
    syscalls = Bunch()
    start = 0
    end = 0
    pred_func = lambda x: False
    mutator = GenericMutator()
    self.assertRaises(ValueError,
                      mutator.find_syscall_between_indexes, syscalls,
                                                            start,
                                                            end,
                                                            pred_func)


  def test_fail_on_end_too_long(self):
    syscalls = [Bunch(), Bunch()]
    start = 0
    end = 3
    pred_func = lambda x: False
    mutator = GenericMutator()
    self.assertRaises(ValueError,
                      mutator.find_syscall_between_indexes, syscalls,
                                                            start,
                                                            end,
                                                            pred_func)


  def test_fail_on_pred_not_callable(self):
    syscalls = [Bunch(), Bunch()]
    start = 0
    end = 1
    pred_func = Bunch()
    mutator = GenericMutator()
    self.assertRaises(TypeError,
                      mutator.find_syscall_between_indexes, syscalls,
                                                            start,
                                                            end,
                                                            pred_func)



  def test_happy_case(self):
    fake_statcall = Bunch()
    fake_statcall.name = 'stat'
    syscalls = [fake_statcall]
    start = 0
    end = 1
    pred_func = lambda x: x.name.startswith('stat')
    mutator = GenericMutator()
    result = mutator.find_syscall_between_indexes(syscalls,
                                                  start,
                                                  end,
                                                  pred_func)
    self.assertEqual(result, [0])
