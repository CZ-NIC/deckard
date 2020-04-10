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
        self.tmpdir = self.get_tmpdir()
        self.tcpdump = None
        self.pcap_path = os.path.join(self.tmpdir, "deckard.pcap")
        os.environ["SOCKET_WRAPPER_PCAP_FILE"] = self.pcap_path

    def __enter__(self):
        try:
            subprocess.run("ip link set dev lo up", check=True, shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError(f"Couldn't set lo device up.")
        cmd = shlex.split("dumpcap -i lo -q -P -w %s" % self.pcap_path)
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

        # TODO: Rewrite so no data is passed via enviroment variables
        os.environ["SOCKET_WRAPPER_DIR"] = tmpdir
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
