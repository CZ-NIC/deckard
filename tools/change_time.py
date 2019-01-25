""" Change time in the test config. """

import fileinput
import time


def change_time(test, newtime=time.strftime("%Y%m%d%H%M%S")):
    """
    change time in the test config to given value
    or to the actual time if it is not set
    """

    with fileinput.FileInput(test, inplace=True, backup='.bak') as file:
        for line in file:
            try:
                if line.split()[0] == "val-override-date:":
                    line = "val-override-date: \"" + newtime + "\"\n"
            except IndexError:
                pass
            print(line, end="")
