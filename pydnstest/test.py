#!/usr/bin/env python
import logging
import os
import time


class Test:
    """ Small library to imitate CMocka output. """
    log = logging.getLogger('pydnstest.test.Test')

    def __init__(self):
        self.tests = []

    def add(self, name, test, args, config):
        """ Add named test to set. """
        self.tests.append((name, test, args, config))

    def run(self):
        """ Run planned tests. """
        planned = len(self.tests)
        passed = 0
        if planned == 0:
            return

        for name, test_callback, args, config in self.tests:
            try:
                test_callback(name, args, config)
                passed += 1
                self.log.info('[  OK  ] %s', name)
            except Exception as e:
                self.log.error('[ FAIL ] %s', name)
                self.log.exception(e)

        # Clear test set
        self.tests = []
        if passed == planned:
            return 0
        else:
            return 1
