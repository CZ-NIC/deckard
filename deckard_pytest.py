import logging
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from ipaddress import ip_address

import dpkt
import pytest

import deckard
from contrib.namespaces import LinuxNamespace
from networking import InterfaceManager


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


class DeckardUnderLoadError(Exception):
    pass


class TCPDump:
    """This context manager captures a PCAP file and than checks it for obvious errors."""

    DUMPCAP_CMD = ["dumpcap", "-i", "any", "-q", "-P", "-w"]

    def __init__(self, config):
        self.config = config
        self.config["tmpdir"] = self.get_tmpdir()
        self.tcpdump = None
        self.config["pcap"] = os.path.join(self.config["tmpdir"], "deckard.pcap")

    def __enter__(self):
        cmd = self.DUMPCAP_CMD.copy()
        cmd.append(self.config["pcap"])
        self.tcpdump = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    def __exit__(self, _, exc_value, __):
        # Wait for the PCAP to be finalized
        while not os.path.exists(self.config["pcap"]):
            time.sleep(1)

        self.tcpdump.terminate()

        self.check_for_unknown_server()

        if exc_value is None:
            if self.config.get('noclean'):
                # Do not clear files if the server crashed (for analysis)
                logging.getLogger('deckard.hint').info(
                    'test working directory %s', self.config["tmpdir"])
            else:
                shutil.rmtree(self.config["tmpdir"])
        else:
            if isinstance(exc_value, ValueError):
                self.check_for_icmp()
            raise

    @staticmethod
    def get_tmpdir():
        if "DECKARD_DIR" in os.environ:
            tmpdir = os.environ["DECKARD_DIR"]
            if os.path.lexists(tmpdir):
                raise ValueError('DECKARD_DIR "%s" must not exist' % tmpdir)
        else:
            tmpdir = tempfile.mkdtemp(suffix='', prefix='tmpdeckard')

        return tmpdir

    def check_for_icmp(self):
        """ Checks Deckards's PCAP for ICMP packets """
        # Deckard's responses to resolvers might be delayed due to load which
        # leads the resolver to close the port and to the test failing in the
        # end. We partially detect these by checking the PCAP for ICMP packets.
        udp_seen = False
        with open(self.config["pcap"], "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for _, packet in pcap:
                ip = dpkt.sll.SLL(packet).data

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp_seen = True

                if udp_seen:
                    if isinstance(ip.data, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                        raise DeckardUnderLoadError("Deckard is under load. "
                                                    "Other errors might be false negatives. "
                                                    "Consider retrying the job later.")

    def check_for_unknown_server(self):
        unknown_addresses = set()
        with open(self.config["pcap"], "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for _, packet in pcap:
                try:
                    ip = dpkt.sll.SLL(packet).data
                    if ip.p != dpkt.ip.IP_PROTO_TCP or ip.p != dpkt.ip.IP_PROTO_UDP:
                        continue
                except (AttributeError, dpkt.dpkt.NeedData):
                    continue
                dest = str(ip_address(ip.dst))
                if dest not in self.config["if_manager"].added_addresses:
                    unknown_addresses.add(dest)

        if unknown_addresses:
            raise RuntimeError("Binary under test queried an IP address not present"
                               " in scenario %s" % unknown_addresses)


def run_test(path, qmin, config, max_retries, retries=0):
    set_coverage_env(path, qmin)

    try:
        with LinuxNamespace("net"):
            config["if_manager"] = InterfaceManager()
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
