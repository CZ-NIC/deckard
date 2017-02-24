#!/usr/bin/env python
import os
import traceback
import time


class Test:
    """ Small library to imitate CMocka output. """

    def __init__(self):
        self.tests = []

    def add(self, name, test, *args):
        """ Add named test to set. """
        self.tests.append((name, test, args))

    def run(self):
        """ Run planned tests. """
        planned = len(self.tests)
        passed = 0
        if planned == 0:
            return

        for name, test_callback, args in self.tests:
            try:
                test_callback(*args)
                passed += 1
                print('[  OK  ] %s' % name)
            except Exception as e:
                print('[ FAIL ] %s (%s)' % (name, str(e)))
                print(traceback.format_exc())

        # Clear test set
        self.tests = []
        if passed == planned:
            return 0
        else:
            return 1
