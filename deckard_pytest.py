import logging
import os
import pytest
import subprocess
import random
import sys
import time

import deckard


def set_coverage_env(path, qmin):
    """Sets up enviroment variables so code coverage utility can work."""
    if os.environ.get("COVERAGE"):
        exports = subprocess.check_output([os.environ["COVERAGE_ENV_SCRIPT"],
                                           os.environ["DAEMONSRCDIR"],
                                           os.environ["COVERAGE_STATSDIR"],
                                           path + "-qmin-" + str(qmin)]).decode()
        for export in exports.split():
            key, value = export.split("=", 1)
            value = value.strip('"')
            os.environ[key] = value


def check_platform():
    if sys.platform == 'windows':
        pytest.exit('Not supported at all on Windows')

# Suppress extensive Augeas logging
logging.getLogger("augeas").setLevel(logging.ERROR)


check_platform()


def run_test(path, qmin, config, retries=0):
    set_coverage_env(path, qmin)
    try:
        del os.environ["SOCKET_WRAPPER_DIR"]
    except KeyError:
        pass
    try:
        deckard.process_file(path, qmin, config)
    except deckard.DeckardUnderLoadError:
        if retries < 3:
            logging.error("Deckard under load. Retrying…")
            # Exponential backoff
            time.sleep((2 ** (retries+1)) + (random.randint(0, 1000) / 1000))
            run_test(path, qmin, config, retries+1)


def test_passes_qmin_on(scenario):
    if scenario.qmin is True or scenario.qmin is None:
        run_test(scenario.path, True, scenario.config)
    else:
        pytest.skip("Query minimization is off in test config")


def test_passes_qmin_off(scenario):
    if scenario.qmin is False or scenario.qmin is None:
        run_test(scenario.path, False, scenario.config)
    else:
        pytest.skip("Query minimization is on in test config")
