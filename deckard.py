#!/usr/bin/env python
import logging
import logging.config
import argparse
import sys
import os
import fileinput
import subprocess
import tempfile
import shutil
import socket
import time
import signal
import stat
import errno
import jinja2
import dns.rdatatype
from pydnstest import scenario, testserver, test
from datetime import datetime
import random
import string
import itertools
import calendar


def str2bool(v):
    """ Return conversion of JSON-ish string value to boolean. """
    return v.lower() in ('yes', 'true', 'on', '1')


def del_files(path_to, delpath):
    for root, dirs, files in os.walk(path_to):
        for f in files:
            os.unlink(os.path.join(root, f))
    if delpath:
        try:
            os.rmdir(path_to)
        except:
            pass

DEFAULT_IFACE = 0
CHILD_IFACE = 0
TMPDIR = ""
OWN_TMPDIR = False
INSTALLDIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FEATURE_LIST_DELIM = ';'
DEFAULT_FEATURE_PAIR_DELIM = '='

if "SOCKET_WRAPPER_DEFAULT_IFACE" in os.environ:
    DEFAULT_IFACE = int(os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"])
if DEFAULT_IFACE < 2 or DEFAULT_IFACE > 254:
    DEFAULT_IFACE = 2
    os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"] = "{}".format(DEFAULT_IFACE)

if "KRESD_WRAPPER_DEFAULT_IFACE" in os.environ:
    CHILD_IFACE = int(os.environ["KRESD_WRAPPER_DEFAULT_IFACE"])
if CHILD_IFACE < 2 or CHILD_IFACE > 254 or CHILD_IFACE == DEFAULT_IFACE:
    OLD_CHILD_IFACE = CHILD_IFACE
    CHILD_IFACE = 254
    if CHILD_IFACE == DEFAULT_IFACE:
        CHILD_IFACE = 253
    os.environ["KRESD_WRAPPER_DEFAULT_IFACE"] = "{}".format(CHILD_IFACE)


if "SOCKET_WRAPPER_DIR" in os.environ:
    TMPDIR = os.environ["SOCKET_WRAPPER_DIR"]
if TMPDIR == "" or os.path.isdir(TMPDIR) is False:
    OLDTMPDIR = TMPDIR
    TMPDIR = tempfile.mkdtemp(suffix='', prefix='tmp')
    OWN_TMPDIR = True
    os.environ["SOCKET_WRAPPER_DIR"] = TMPDIR


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


def setup_env(scenario, child_env, config, args):
    """ Set up test environment and config """
    log = logging.getLogger('deckard.setup_env')
    # Clear test directory
    del_files(TMPDIR, False)
    # Set up libfaketime
    os.environ["FAKETIME_NO_CACHE"] = "1"
    os.environ["FAKETIME_TIMESTAMP_FILE"] = '%s/.time' % TMPDIR
    child_env["FAKETIME_NO_CACHE"] = "1"
    child_env["FAKETIME_TIMESTAMP_FILE"] = '%s/.time' % TMPDIR
    write_timestamp_file(child_env["FAKETIME_TIMESTAMP_FILE"], int(time.time()))
    # Set up child process env()
    child_env["SOCKET_WRAPPER_DEFAULT_IFACE"] = "%i" % CHILD_IFACE
    child_env["SOCKET_WRAPPER_DIR"] = TMPDIR
    # do not pass SOCKET_WRAPPER_PCAP_FILE into child to avoid duplicate packets in pcap
    if "SOCKET_WRAPPER_PCAP_FILE" in child_env:
        del child_env["SOCKET_WRAPPER_PCAP_FILE"]
    qmin = args.qmin
    do_not_query_localhost = True
    trust_anchor_list = []
    stub_addr = ""
    features = {}
    feature_list_delimiter = DEFAULT_FEATURE_LIST_DELIM
    feature_pair_delimiter = DEFAULT_FEATURE_PAIR_DELIM
    selfaddr = testserver.get_local_addr_str(socket.AF_INET, DEFAULT_IFACE)
    for k, v in config:
        # Enable selectively for some tests
        if k == 'do-not-query-localhost':
            do_not_query_localhost = str2bool(v)
        if k == 'query-minimization':
            qmin = str2bool(v)
        elif k == 'trust-anchor':
            trust_anchor_list.append(v.strip('"\''))
        elif k == 'val-override-timestamp':
            override_timestamp_str = v.strip('"\'')
            write_timestamp_file(child_env["FAKETIME_TIMESTAMP_FILE"], int(override_timestamp_str))
        elif k == 'val-override-date':
            override_date_str = v.strip('"\'')
            ovr_yr = override_date_str[0:4]
            ovr_mnt = override_date_str[4:6]
            ovr_day = override_date_str[6:8]
            ovr_hr = override_date_str[8:10]
            ovr_min = override_date_str[10:12]
            ovr_sec = override_date_str[12:]
            override_date_str_arg = '{0} {1} {2} {3} {4} {5}'.format(
                ovr_yr, ovr_mnt, ovr_day, ovr_hr, ovr_min, ovr_sec)
            override_date = time.strptime(override_date_str_arg, "%Y %m %d %H %M %S")
            override_date_timestamp = calendar.timegm(override_date)
            write_timestamp_file(child_env["FAKETIME_TIMESTAMP_FILE"], override_date_timestamp)
        elif k == 'stub-addr':
            stub_addr = v.strip('"\'')
        elif k == 'features':
            feature_list = v.split(feature_list_delimiter)
            try:
                for f_item in feature_list:
                    if f_item.find(feature_pair_delimiter) != -1:
                        f_key, f_value = [x.strip()
                                          for x
                                          in f_item.split(feature_pair_delimiter, 1)]
                    else:
                        f_key = f_item.strip()
                        f_value = ""
                    features[f_key] = f_value
            except Exception as e:
                raise Exception("can't parse features (%s) in config section (%s)" % (v, str(e)))
        elif k == 'feature-list':
            try:
                f_key, f_value = [x.strip() for x in v.split(feature_pair_delimiter, 1)]
                if f_key not in features:
                    features[f_key] = []
                f_value = f_value.replace("{{INSTALL_DIR}}", INSTALLDIR)
                features[f_key].append(f_value)
            except Exception as e:
                raise Exception("can't parse feature-list (%s) in config section (%s)"
                                % (v, str(e)))
        elif k == 'force-ipv6' and v.upper() == 'TRUE':
            scenario.sockfamily = socket.AF_INET6

    if stub_addr != "":
        selfaddr = stub_addr
    else:
        selfaddr = testserver.get_local_addr_str(scenario.sockfamily, DEFAULT_IFACE)
    childaddr = testserver.get_local_addr_str(scenario.sockfamily, CHILD_IFACE)
    # Prebind to sockets to create necessary files
    # @TODO: this is probably a workaround for socket_wrapper bug
    if 'NOPRELOAD' not in os.environ:
        for sock_type in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            sock = socket.socket(scenario.sockfamily, sock_type)
            sock.setsockopt(scenario.sockfamily, socket.SO_REUSEADDR, 1)
            sock.bind((childaddr, 53))
            if sock_type & socket.SOCK_STREAM:
                sock.listen(5)
    # Generate configuration files
    j2template_loader = jinja2.FileSystemLoader(
        searchpath=os.path.dirname(os.path.abspath(__file__)))
    j2template_env = jinja2.Environment(loader=j2template_loader)
    j2template_ctx = {
        "DO_NOT_QUERY_LOCALHOST": str(do_not_query_localhost).lower(),
        "ROOT_ADDR": selfaddr,
        "SELF_ADDR": childaddr,
        "QMIN": str(qmin).lower(),
        "TRUST_ANCHORS": trust_anchor_list,
        "WORKING_DIR": TMPDIR,
        "INSTALL_DIR": INSTALLDIR,
        "FEATURES": features
    }
    log.debug('values for templates: %s', j2template_ctx)

    for template_name, config_name in zip(args.templates, args.configs):
        j2template = j2template_env.get_template(template_name)
        cfg_rendered = j2template.render(j2template_ctx)
        f = open(os.path.join(TMPDIR, config_name), 'w')
        f.write(cfg_rendered)
        f.close()


def play_object(path, args):
    """ Play scenario from a file object. """
    daemon_logger_log = logging.getLogger('deckard.daemon.log')

    # Parse scenario
    case, config = scenario.parse_file(fileinput.input(path))

    # Setup daemon environment
    daemon_env = os.environ.copy()
    setup_env(case, daemon_env, config, args)

    server = testserver.TestServer(case, config, DEFAULT_IFACE)
    server.start()

    ignore_exit = bool(os.environ.get('IGNORE_EXIT_CODE', 0))
    # Start binary
    daemon_proc = None
    daemon_log_path = open('%s/server.log' % TMPDIR, 'w')
    daemon_args = [args.binary] + args.additional
    logging.getLogger('deckard.daemon.env').debug('%s', daemon_env)
    logging.getLogger('deckard.daemon.argv').debug('%s', daemon_args)
    try:
        daemon_proc = subprocess.Popen(daemon_args, stdout=daemon_log_path, stderr=daemon_log_path,
                                       cwd=TMPDIR, preexec_fn=os.setsid, env=daemon_env)
    except Exception as e:
        server.stop()
        msg = "Can't start '%s': %s" % (daemon_args, str(e))
        daemon_logger_log.critical(msg)
        raise Exception(msg)

    # Wait until the server accepts TCP clients
    sock = socket.socket(case.sockfamily, socket.SOCK_STREAM)
    while True:
        time.sleep(0.1)
        if daemon_proc.poll():
            server.stop()
            msg = 'process died "%s", logs in "%s"' % (os.path.basename(args.binary), TMPDIR)
            daemon_logger_log.critical(msg)
            daemon_logger_log.error(open('%s/server.log' % TMPDIR).read())
            raise Exception(msg)
        try:
            sock.connect((testserver.get_local_addr_str(case.sockfamily, CHILD_IFACE), 53))
        except:
            continue
        break
    sock.close()

    # Bind to test servers
    for r in case.ranges:
        for addr in r.addresses:
            family = socket.AF_INET6 if ':' in addr else socket.AF_INET
            server.start_srv((addr, 53), family)
    # Bind addresses in ad-hoc REPLYs
    for s in case.steps:
        if s.type == 'REPLY':
            reply = s.data[0].message
            for rr in itertools.chain(reply.answer,
                                      reply.additional,
                                      reply.question,
                                      reply.authority):
                for rd in rr:
                    if rd.rdtype == dns.rdatatype.A:
                        server.start_srv((rd.address, 53), socket.AF_INET)
                    elif rd.rdtype == dns.rdatatype.AAAA:
                        server.start_srv((rd.address, 53), socket.AF_INET6)

    # Play test scenario
    try:
        server.play(CHILD_IFACE)
    finally:
        server.stop()
        daemon_proc.terminate()
        daemon_proc.wait()
        daemon_logger_log = logging.getLogger('deckard.daemon_log')
        daemon_logger_log.debug(open('%s/server.log' % TMPDIR).read())
        if daemon_proc.returncode != 0 and not ignore_exit:
            raise ValueError('process terminated with return code %s'
                             % daemon_proc.returncode)
    # Do not clear files if the server crashed (for analysis)
    del_files(TMPDIR, OWN_TMPDIR)
    if server.undefined_answers > 0:
        raise ValueError('the scenario does not define all necessary answers (see error log)')


def test_platform(*args):
    if sys.platform == 'windows':
        raise NotImplementedError('not supported at all on Windows')

if __name__ == '__main__':
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
                           action=EnvDefault, envvar='QMIN', type=str2bool)
    argparser.add_argument('--loglevel', help='verbosity (default: errors + test results)',
                           action=EnvDefault, envvar='VERBOSE',
                           type=loglevel2number, required=False)
    argparser.add_argument('scenario', help='path to test scenario')
    argparser.add_argument('binary', help='executable to test')
    argparser.add_argument('templates', help='colon-separated list of jinja2 template files',
                           action=ColonSplitter)
    argparser.add_argument('configs',
                           help='colon-separated list of files to be generated from templates',
                           action=ColonSplitter)
    argparser.add_argument('additional', help='additional parameters for the binary', nargs='*')
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

    if len(args.templates) != len(args.configs):
        log.critical('Number of jinja2 template files is not equal '
                     'to number of config files to be generated, '
                     'i.e. len(templates) != len(configs)')
        sys.exit(1)

    # Scan for scenarios
    test = test.Test()
    objects = find_objects(args.scenario)
    for path in objects:
        test.add(path, play_object, args)
    sys.exit(test.run())
