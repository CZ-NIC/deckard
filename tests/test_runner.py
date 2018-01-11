"""Usage: run `LD_PRELOAD="«paths to libfaketime and libsocket_wrapper»"
py.test tests/test_experiment` in deckard's root directory.
Alternatively add `-n «number of cores»` with `pytest-xdist` module installed.
"""
import logging
import os
import pytest
import subprocess
import sys

import deckard


def set_coverage_env(path, qmin):
    """Sets up enviroment variables so code coverage utility can work."""
    if os.environ.get("COVERAGE"):
        exports = subprocess.check_output([os.environ["COVERAGE_ENV_SCRIPT"],
                                           os.environ["DEAMONSRCDIR"],
                                           os.environ["COVERAGE_STATSDIR"],
                                           path + "-qmin-" + str(qmin)]).decode()
        for export in exports.split():
            key = export.split("=")[0]
            value = export.split("=")[1]
            os.environ[key] = value


def check_platform():
    if sys.platform == 'windows':
        pytest.exit('Not supported at all on Windows')

# Suppress extensive Augeas logging
logging.getLogger("augeas").setLevel(logging.ERROR)


check_platform()


def run_test(path, qmin, config):
    set_coverage_env(path, qmin)
    try:
        del os.environ["SOCKET_WRAPPER_DIR"]
    except KeyError:
        pass
    deckard.process_file(path, qmin, config)


def test_passes_qmin_on(scenario, config):
    if scenario.qmin is True or scenario.qmin is None:
        run_test(scenario.path, True, config)
    else:
        pytest.skip("Query minimization is off in test config")


def test_passes_qmin_off(scenario, config):
    if scenario.qmin is False or scenario.qmin is None:
        run_test(scenario.path, False, config)
    else:
        pytest.skip("Query minimization is on in test config")
