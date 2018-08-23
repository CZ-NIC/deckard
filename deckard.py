#!/usr/bin/env python3
from datetime import datetime
import errno
import logging
import logging.config
import os
import shutil
import socket
import subprocess
import tempfile
import time

import dpkt
import jinja2

from pydnstest import scenario, testserver


# path to Deckard files
INSTALLDIR = os.path.dirname(os.path.abspath(__file__))
# relative to working directory
TRUST_ANCHOR_SUBDIR = 'ta'


class DeckardUnderLoadError(Exception):
    pass


class IfaceManager(object):
    """
    Network interface allocation manager

    Keeps mapping between 'name', interface number, and IP address.
    """
    def __init__(self, sockfamily):
        """
        Parameters:
            sockfamily Address family used in given test scenatio
                       (a constant from socket module)
        """
        if sockfamily not in {socket.AF_INET, socket.AF_INET6}:
            raise NotImplementedError("address family not supported '%i'" % sockfamily)
        self.sockfamily = sockfamily
        self.free = list(range(40, 10, -1))  # range accepted by libswrap
        self.name2iface = {}

    def allocate(self, name):
        """
        Map name to a free interface number.
        """
        if name in self.name2iface:
            raise ValueError('duplicate interface name %s' % name)
        iface = str(self.free.pop())
        self.name2iface[name] = iface
        return iface

    def getiface(self, name):
        """
        Map name to allocated interface number.

        Returns:
            Interface number as string (so it can be assigned to os.environ)
        """
        return self.name2iface[name]

    def getipaddr(self, name):
        """
        Get default IP address assigned to interface allocated to given name.

        Returns:
            Address from address family specified during IfaceManager init.
        """
        iface = self.getiface(name)
        if self.sockfamily == socket.AF_INET:
            addr_local_pattern = "127.0.0.{}"
        elif self.sockfamily == socket.AF_INET6:
            addr_local_pattern = "fd00::5357:5f{:02X}"
        return addr_local_pattern.format(int(iface))

    def getalladdrs(self):
        """
        Get mapping from all names to all IP addresses.

        Returns:
            {name: IP address}
        """
        return {name: self.getipaddr(name)
                for name in self.name2iface}


def write_timestamp_file(path, tst):
    time_file = open(path, 'w')
    time_file.write(datetime.fromtimestamp(tst).strftime('@%Y-%m-%d %H:%M:%S'))
    time_file.flush()
    time_file.close()


def setup_common_env(ctx):
    """
    Setup environment shared between Deckard and binaries under test.

    Environment for child processes must be based on on.environ as modified
    by this function.

    Returns:
        path to working directory
    """
    # working directory
    if "SOCKET_WRAPPER_DIR" in os.environ:
        tmpdir = os.environ["SOCKET_WRAPPER_DIR"]
        if os.path.lexists(tmpdir):
            raise ValueError('SOCKET_WRAPPER_DIR "%s" must not exist' % tmpdir)
    else:
        tmpdir = tempfile.mkdtemp(suffix='', prefix='tmpdeckard')

    # Set up libfaketime
    os.environ["FAKETIME_NO_CACHE"] = "1"
    os.environ["FAKETIME_TIMESTAMP_FILE"] = '%s/.time' % tmpdir
    # fake initial time
    write_timestamp_file(os.environ["FAKETIME_TIMESTAMP_FILE"],
                         ctx.get('_OVERRIDE_TIMESTAMP', time.time()))

    # Set up socket_wrapper
    os.environ["SOCKET_WRAPPER_DIR"] = tmpdir
    os.environ["SOCKET_WRAPPER_PCAP_FILE"] = '%s/deckard.pcap' % tmpdir

    return tmpdir


def setup_daemon_env(prog_cfg, tmpdir):
    """ Set up test environment and config """
    name = prog_cfg['name']
    log = logging.getLogger('deckard.daemon.%s.setup_env' % name)
    # Set up child process env() to use socket wrapper interface
    child_env = os.environ.copy()
    child_env['SOCKET_WRAPPER_DEFAULT_IFACE'] = prog_cfg['iface']
    prog_cfg['dir'] = os.path.join(tmpdir, name)
    log.debug('directory: %s', prog_cfg['dir'])
    child_env['SOCKET_WRAPPER_PCAP_FILE'] = '%s/pcap' % prog_cfg['dir']

    return child_env


def setup_network(sockfamily, prog_cfgs):
    """Allocate fake interfaces and IP addresses to all entities.

    Returns:
    - SOCKET_WRAPPER_DEFAULT_IFACE will be set in os.environ
    - Dict suitable for usage in Jinja2 templates will be returned
        {
         ROOT_ADDR: <DeckardIP>,
         IPADDRS: {name: <IPaddress>}
        }
    """
    net_config = {}
    # assign interfaces and IP addresses to all involved programs
    ifacemgr = IfaceManager(sockfamily)
    # fake interface for Deckard itself
    deckard_iface = ifacemgr.allocate('deckard')
    os.environ['SOCKET_WRAPPER_DEFAULT_IFACE'] = deckard_iface
    net_config['ROOT_ADDR'] = ifacemgr.getipaddr('deckard')

    for prog_cfg in prog_cfgs['programs']:
        prog_cfg['iface'] = ifacemgr.allocate(prog_cfg['name'])
        prog_cfg['ipaddr'] = ifacemgr.getipaddr(prog_cfg['name'])
    net_config['IPADDRS'] = ifacemgr.getalladdrs()

    return net_config


def _fixme_prebind_hack(sockfamily, childaddr):
    """
    Prebind to sockets to create necessary files

    @TODO: this is probably a workaround for socket_wrapper bug
    """
    if 'NOPRELOAD' not in os.environ:
        for sock_type in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            sock = socket.socket(sockfamily, sock_type)
            sock.setsockopt(sockfamily, socket.SO_REUSEADDR, 1)
            sock.bind((childaddr, 53))
            if sock_type & socket.SOCK_STREAM:
                sock.listen(5)


def create_trust_anchor_files(ta_files, work_dir):
    """
    Write trust anchor files in specified working directory.

    Params:
      ta_files Dict {domain name: [TA lines]}
    Returns:
      List of absolute filesystem paths to TA files.
    """
    full_paths = []
    for domain, ta_lines in ta_files.items():
        file_name = u'{}.key'.format(domain)
        full_path = os.path.realpath(
            os.path.join(work_dir, TRUST_ANCHOR_SUBDIR, file_name))
        full_paths.append(full_path)
        dir_path = os.path.dirname(full_path)
        try:
            os.makedirs(dir_path)
        except OSError as ex:
            if ex.errno != errno.EEXIST:
                raise
        with open(full_path, "w") as ta_file:
            ta_file.writelines('{0}\n'.format(l) for l in ta_lines)
    return full_paths


def setup_daemon_files(prog_cfg, template_ctx, ta_files):
    name = prog_cfg['name']
    # add program-specific variables
    subst = template_ctx.copy()
    subst['DAEMON_NAME'] = name

    subst['WORKING_DIR'] = prog_cfg['dir']
    os.mkdir(prog_cfg['dir'])
    subst['SELF_ADDR'] = prog_cfg['ipaddr']

    # daemons might write to TA files so every daemon gets its own copy
    subst['TRUST_ANCHOR_FILES'] = create_trust_anchor_files(
        ta_files, prog_cfg['dir'])

    # generate configuration files
    j2template_loader = jinja2.FileSystemLoader(searchpath=os.getcwd())
    print(os.path.abspath(os.getcwd()))
    j2template_env = jinja2.Environment(loader=j2template_loader)
    logging.getLogger('deckard.daemon.%s.template' % name).debug(subst)

    assert len(prog_cfg['templates']) == len(prog_cfg['configs'])
    for template_name, config_name in zip(prog_cfg['templates'], prog_cfg['configs']):
        j2template = j2template_env.get_template(template_name)
        cfg_rendered = j2template.render(subst)
        with open(os.path.join(prog_cfg['dir'], config_name), 'w') as output:
            output.write(cfg_rendered)

    _fixme_prebind_hack(template_ctx['_SOCKET_FAMILY'], subst['SELF_ADDR'])


def run_daemon(cfg, environ):
    """Start binary and return its process object"""
    name = cfg['name']
    proc = None
    cfg['log'] = os.path.join(cfg['dir'], 'server.log')
    daemon_log_file = open(cfg['log'], 'w')
    cfg['args'] = args = [cfg['binary']] + cfg['additional']
    logging.getLogger('deckard.daemon.%s.env' % name).debug('%s', environ)
    logging.getLogger('deckard.daemon.%s.argv' % name).debug('%s', args)
    try:
        proc = subprocess.Popen(args, stdout=daemon_log_file, stderr=subprocess.STDOUT,
                                cwd=cfg['dir'], preexec_fn=os.setsid, env=environ)
    except subprocess.CalledProcessError:
        logger = logging.getLogger('deckard.daemon_log.%s' % name)
        logger.exception("Can't start '%s'", args)
        raise
    return proc


def conncheck_daemon(process, cfg, sockfamily):
    """Wait until the server accepts TCP clients"""
    sock = socket.socket(sockfamily, socket.SOCK_STREAM)
    while True:
        time.sleep(0.1)
        if process.poll():
            msg = 'process died "%s", logs in "%s"' % (cfg['name'], cfg['dir'])
            logger = logging.getLogger('deckard.daemon_log.%s' % cfg['name'])
            logger.critical(msg)
            logger.error(open(cfg['log']).read())
            raise subprocess.CalledProcessError(process.returncode, cfg['args'], msg)
        try:
            sock.connect((cfg['ipaddr'], 53))
        except socket.error:
            continue
        break
    sock.close()


def process_file(path, qmin, prog_cfgs):
    """Parse scenario from a file object and create workdir."""
    # Parse scenario
    case, cfg_text = scenario.parse_file(os.path.realpath(path))
    cfg_ctx, ta_files = scenario.parse_config(cfg_text, qmin, INSTALLDIR)
    template_ctx = setup_network(cfg_ctx['_SOCKET_FAMILY'], prog_cfgs)
    # merge variables from scenario with generated network variables (scenario has priority)
    template_ctx.update(cfg_ctx)
    # Deckard will communicate with first program
    prog_under_test = prog_cfgs['programs'][0]['name']
    prog_under_test_ip = template_ctx['IPADDRS'][prog_under_test]

    # get working directory and environment variables
    tmpdir = setup_common_env(cfg_ctx)
    shutil.copy2(path, os.path.join(tmpdir))
    try:
        daemons = setup_daemons(tmpdir, prog_cfgs, template_ctx, ta_files)
        run_testcase(daemons,
                     case,
                     template_ctx['ROOT_ADDR'],
                     template_ctx['_SOCKET_FAMILY'],
                     prog_under_test_ip)
        if prog_cfgs.get('noclean'):
            logging.getLogger('deckard.hint').info(
                'test working directory %s', tmpdir)
        else:
            shutil.rmtree(tmpdir)
    except:
        logging.getLogger('deckard.hint').info(
            'test failed, inspect working directory %s', tmpdir)
        raise


def setup_daemons(tmpdir, prog_cfgs, template_ctx, ta_files):
    """Configure daemons and run the test"""
    # Setup daemon environment
    daemons = []
    for prog_cfg in prog_cfgs['programs']:
        daemon_env = setup_daemon_env(prog_cfg, tmpdir)
        setup_daemon_files(prog_cfg, template_ctx, ta_files)
        daemon_proc = run_daemon(prog_cfg, daemon_env)
        daemons.append({'proc': daemon_proc, 'cfg': prog_cfg})
        try:
            conncheck_daemon(daemon_proc, prog_cfg, template_ctx['_SOCKET_FAMILY'])
        except:
            daemon_proc.terminate()
            raise
    return daemons


def check_for_icmp():
        """ Checks Deckards's PCAP for ICMP packets """
        # Deckard's responses to resolvers might be delayed due to load which
        # leads the resolver to close the port and to the test failing in the
        # end. We partially detect these by checking the PCAP for ICMP packets.
        path = os.environ["SOCKET_WRAPPER_PCAP_FILE"]
        udp_seen = False
        with open(path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for _, packet in pcap:
                try:
                    ip = dpkt.ip.IP(packet)
                except dpkt.dpkt.UnpackError:
                    ip = dpkt.ip6.IP6(packet)
                if isinstance(ip.data, dpkt.udp.UDP):
                    udp_seen = True

                if udp_seen:
                    if isinstance(ip.data, dpkt.icmp.ICMP) or isinstance(ip.data, dpkt.icmp6.ICMP6):
                        raise DeckardUnderLoadError("Deckard is under load. "
                                                    "Other errors might be false negatives. "
                                                    "Consider retrying the job later.")
            return False


def run_testcase(daemons, case, root_addr, addr_family, prog_under_test_ip):
    """Run actual test and raise exception if the test failed"""
    server = testserver.TestServer(case, root_addr, addr_family)
    server.start()

    try:
        server.play(prog_under_test_ip)
    except ValueError as e:
        if not check_for_icmp():
            raise e
    finally:
        server.stop()
        for daemon in daemons:
            daemon['proc'].terminate()
            daemon['proc'].wait()
            daemon_logger_log = logging.getLogger('deckard.daemon_log.%s' % daemon['cfg']['name'])
            with open(daemon['cfg']['log']) as logf:
                for line in logf:
                    daemon_logger_log.debug(line.strip())
            ignore_exit = daemon["cfg"].get('ignore_exit_code', False)
            if daemon['proc'].returncode != 0 and not ignore_exit:
                raise ValueError('process %s terminated with return code %s'
                                 % (daemon['cfg']['name'], daemon['proc'].returncode))
    # Do not clear files if the server crashed (for analysis)
    if server.undefined_answers > 0:
        if not check_for_icmp():
            raise ValueError('the scenario does not define all necessary answers (see error log)')
