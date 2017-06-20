#!/usr/bin/env python
import argparse
from datetime import datetime
import logging
import logging.config
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import jinja2
import yaml

from pydnstest import scenario, testserver, test


# path to Deckard files
INSTALLDIR = os.path.dirname(os.path.abspath(__file__))


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


def find_objects(path):
    """ Recursively scan file/directory for scenarios. """
    result = []
    if os.path.isdir(path):
        for e in os.listdir(path):
            result += find_objects(os.path.join(path, e))
    elif os.path.isfile(path):
        if path.endswith('.rpl'):
            result.append(path)
    return result


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


def setup_daemon_files(prog_cfg, template_ctx):
    name = prog_cfg['name']
    # add program-specific variables
    subst = template_ctx.copy()
    subst['DAEMON_NAME'] = name

    subst['WORKING_DIR'] = prog_cfg['dir']
    os.mkdir(prog_cfg['dir'])

    subst['SELF_ADDR'] = prog_cfg['ipaddr']

    # generate configuration files
    j2template_loader = jinja2.FileSystemLoader(
        searchpath=os.path.dirname(os.path.abspath(__file__)))
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


def play_object(path, args, prog_cfgs):
    """ Play scenario from a file object. """
    daemon_logger_log = logging.getLogger('deckard.daemon.log')

    # Parse scenario
    case, cfg_text = scenario.parse_file(os.path.realpath(path))
    cfg_ctx = scenario.parse_config(cfg_text, args.qmin, INSTALLDIR)

    # get working directory and environment variables
    tmpdir = setup_common_env(cfg_ctx)
    template_ctx = setup_network(cfg_ctx['_SOCKET_FAMILY'], prog_cfgs)
    # merge variables from scenario with generated network variables (scenario has priority)
    template_ctx.update(cfg_ctx)

    # Setup daemon environment
    daemons = []
    for prog_cfg in prog_cfgs['programs']:
        daemon_env = setup_daemon_env(prog_cfg, tmpdir)
        setup_daemon_files(prog_cfg, template_ctx)
        daemon_proc = run_daemon(prog_cfg, daemon_env)
        daemons.append({'proc': daemon_proc, 'cfg': prog_cfg})
        conncheck_daemon(daemon_proc, prog_cfg, template_ctx['_SOCKET_FAMILY'])

    # Play test scenario
    server = testserver.TestServer(case, template_ctx['ROOT_ADDR'], template_ctx['_SOCKET_FAMILY'])
    server.start()

    # Deckard will communicate with first program
    prog_under_test = prog_cfgs['programs'][0]['name']
    prog_under_test_ip = template_ctx['IPADDRS'][prog_under_test]
    try:
        server.play(prog_under_test_ip)
    finally:
        server.stop()
        for daemon in daemons:
            daemon['proc'].terminate()
            daemon['proc'].wait()
            daemon_logger_log = logging.getLogger('deckard.daemon_log.%s' % daemon['cfg']['name'])
            with open(daemon['cfg']['log']) as logf:
                for line in logf:
                    daemon_logger_log.debug(line.strip())
            ignore_exit = bool(os.environ.get('IGNORE_EXIT_CODE', 0))
            if daemon['proc'].returncode != 0 and not ignore_exit:
                raise ValueError('process %s terminated with return code %s'
                                 % (daemon['cfg']['name'], daemon['proc'].returncode))
    # Do not clear files if the server crashed (for analysis)
    shutil.rmtree(tmpdir)
    if server.undefined_answers > 0:
        raise ValueError('the scenario does not define all necessary answers (see error log)')


def test_platform():
    if sys.platform == 'windows':
        raise NotImplementedError('not supported at all on Windows')


def deckard():
    # auxilitary classes for argparse
    class ColonSplitter(argparse.Action):  # pylint: disable=too-few-public-methods
        """Split argument string into list holding items separated by colon."""
        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, values.split(':'))

    class EnvDefault(argparse.Action):  # pylint: disable=too-few-public-methods
        """Get default value for parameter from environment variable."""
        def __init__(self, envvar, required=True, default=None, **kwargs):
            if envvar and envvar in os.environ:
                default = os.environ[envvar]
            if required and default is not None:
                required = False
            super(EnvDefault, self).__init__(default=default, required=required, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, values)

    def loglevel2number(level):
        """Convert direct log level number or symbolic name to a number."""
        try:
            return int(level)
        except ValueError:
            pass  # not a number, try if it is a named constant from logging module
        try:
            return getattr(logging, level.upper())
        except AttributeError:
            raise ValueError('unknown log level %s' % level)

    test_platform()

    argparser = argparse.ArgumentParser()
    argparser.add_argument('--qmin', help='query minimization (default: enabled)', default=True,
                           action=EnvDefault, envvar='QMIN', type=scenario.str2bool)
    argparser.add_argument('--loglevel', help='verbosity (default: errors + test results)',
                           action=EnvDefault, envvar='VERBOSE',
                           type=loglevel2number, required=False)
    argparser.add_argument('scenario', help='path to test scenario')

    subparsers = argparser.add_subparsers(
        dest='cmd', title='sub-commands',
        description='run scenario with one binary specified on command line '
                    'or multiple binaries specified in config file')

    run_one = subparsers.add_parser('one', help='run single binary inside single scenario')
    run_one.add_argument('binary', help='executable to test')
    run_one.add_argument('templates', help='colon-separated list of jinja2 template files',
                         action=ColonSplitter)
    run_one.add_argument('configs',
                         help='colon-separated list of files to be generated from templates',
                         action=ColonSplitter)
    run_one.add_argument('additional', help='additional parameters for the binary', nargs='*')

    run_cfg = subparsers.add_parser(
        'multiple',
        help='run all binaries specified in YaML file; '
             'all binaries will be executed inside single scenario')
    run_cfg.add_argument('yaml', help='YaML specifying binaries and their parameter',
                         type=open)
    args = argparser.parse_args()

    if not args.loglevel:
        # default verbosity: errors + test results
        args.loglevel = logging.ERROR
        logging.config.dictConfig(
            {
                'version': 1,
                'incremental': True,
                'loggers': {
                    'pydnstest.test.Test': {'level': 'INFO'}
                }
            })

    if args.loglevel <= logging.DEBUG:  # include message origin
        logging.basicConfig(level=args.loglevel)
    else:
        logging.basicConfig(level=args.loglevel, format='%(message)s')
    log = logging.getLogger('deckard')

    if args.cmd == 'multiple':
        config = yaml.load(args.yaml)
    else:
        assert args.cmd == 'one'
        config = {
            'programs': [{
                'binary': args.binary,
                'templates': args.templates,
                'configs': args.configs,
                'additional': args.additional,
                'name': os.path.basename(args.binary),
            }]}

    mandatory_keys = {'name', 'binary', 'templates', 'configs', 'additional'}
    for cfg in config['programs']:
        missing_keys = mandatory_keys - set(cfg.keys())
        if missing_keys:
            log.critical('Mandatory fields in configuration are missing: %s', missing_keys)
            sys.exit(1)

        # sanity check templates vs. configs
        if len(cfg['templates']) != len(cfg['configs']):
            log.critical('Number of jinja2 template files is not equal '
                         'to number of config files to be generated for '
                         'program "%s", i.e. len(templates) != len(configs)',
                         cfg['name'])
            sys.exit(1)

    # Scan for scenarios
    testset = test.Test()
    objects = find_objects(args.scenario)
    for path in objects:
        testset.add(path, play_object, args, config)
    sys.exit(testset.run())


if __name__ == '__main__':
    # this is done to avoid creating global variables
    deckard()
