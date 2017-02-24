from __future__ import print_function

import os
import threading

dprint_lock = threading.Lock()

def dprint(tag, msg):
    """ Verbose logging (if enabled). """
    if 'VERBOSE' in os.environ:
        dprint_lock.acquire()
        print(tag, msg)
        dprint_lock.release()
