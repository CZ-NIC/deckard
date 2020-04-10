import logging
import os
import subprocess
import random
import shlex
import sys
import time
import tempfile

import pytest

import deckard
from namespaces import LinuxNamespace
import networking


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

class TCPDump:
    def __init__(self, config):
        self.config = config
        self.config["tmpdir"] = self.get_tmpdir()
        self.tcpdump = None
        self.config["pcap"] = os.path.join(self.config["tmpdir"], "deckard.pcap")

    def __enter__(self):
        cmd = shlex.split("dumpcap -i lo -q -P -w %s" % self.config["pcap"])
        self.tcpdump = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    def __exit__(self, *exc):
        self.tcpdump.terminate()

    def get_tmpdir(self):
        if "DECKARD_DIR" in os.environ:
            tmpdir = os.environ["DECKARD_DIR"]
            if os.path.lexists(tmpdir):
                raise ValueError('DECKARD_DIR "%s" must not exist' % tmpdir)
        else:
            tmpdir = tempfile.mkdtemp(suffix='', prefix='tmpdeckard')

        print(tmpdir)
        return tmpdir

def run_test(path, qmin, config, max_retries, retries=0):
    set_coverage_env(path, qmin)
    try:
        del os.environ["SOCKET_WRAPPER_DIR"]
    except KeyError:
        pass
    try:
        with LinuxNamespace("net"):
            config["lo_manager"] = networking.LoopbackManager()
            with TCPDump(config):
                deckard.process_file(path, qmin, config)
    except deckard.DeckardUnderLoadError as e:
        if retries < max_retries:
            logging.error("Deckard under load. Retrying…")
            # Exponential backoff
            time.sleep((2 ** retries) + random.random())
            run_test(path, qmin, config, max_retries, retries + 1)
        else:
            raise e


def test_passes_qmin_on(scenario, max_retries):
    if scenario.qmin is True or scenario.qmin is None:
        run_test(scenario.path, True, scenario.config, max_retries)
    else:
        pytest.skip("Query minimization is off in test config")


def test_passes_qmin_off(scenario, max_retries):
    if scenario.qmin is False or scenario.qmin is None:
        run_test(scenario.path, False, scenario.config, max_retries)
    else:
        pytest.skip("Query minimization is on in test config")
