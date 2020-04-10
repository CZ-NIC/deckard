#!/usr/bin/env python3
import errno
import logging
import logging.config
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime
from typing import Set  # noqa

import jinja2

from pydnstest import scenario, testserver

# path to Deckard files
INSTALLDIR = os.path.dirname(os.path.abspath(__file__))
# relative to working directory
TRUST_ANCHOR_SUBDIR = 'ta'


class DeckardUnderLoadError(Exception):
    pass


def setup_internal_addresses(config):
    config["DECKARD_IP"] = config["if_manager"].add_internal_address(config["_SOCKET_FAMILY"])
    for program in config["programs"]:
        program["address"] = config["if_manager"].add_internal_address(config["_SOCKET_FAMILY"])


def write_timestamp_file(path, tst):
    time_file = open(path, 'w')
    time_file.write(datetime.fromtimestamp(tst).strftime('@%Y-%m-%d %H:%M:%S'))
    time_file.flush()
    time_file.close()


def setup_faketime(config):
    """
    Setup environment shared between Deckard and binaries under test.

    Environment for child processes must be based on on.environ as modified
    by this function.

    Returns:
        path to working directory
    """
    # Set up libfaketime
    os.environ["FAKETIME_NO_CACHE"] = "1"
    os.environ["FAKETIME_TIMESTAMP_FILE"] = os.path.join(config["tmpdir"], ".time")
    os.unsetenv("FAKETIME")

    write_timestamp_file(os.environ["FAKETIME_TIMESTAMP_FILE"],
                         config.get('_OVERRIDE_TIMESTAMP', time.time()))


def setup_daemon_environment(program_config, global_config):
    program_config["WORKING_DIR"] = os.path.join(global_config["tmpdir"], program_config["name"])
    os.mkdir(program_config['WORKING_DIR'])
    program_config["DAEMON_NAME"] = program_config["name"]
    program_config['SELF_ADDR'] = program_config['address']
    program_config['TRUST_ANCHOR_FILES'] = create_trust_anchor_files(
    global_config["TRUST_ANCHOR_FILES"], program_config['WORKING_DIR'])


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


def generate_from_templates(program_config, global_config):
    """Generate configuration for the program"""
    config = global_config.copy()
    config.update(program_config)

    j2template_loader = jinja2.FileSystemLoader(searchpath=os.getcwd())
    j2template_env = jinja2.Environment(loader=j2template_loader)

    for template_name, config_name in zip(config['templates'], config['configs']):
        j2template = j2template_env.get_template(template_name)
        cfg_rendered = j2template.render(config)
        with open(os.path.join(config['WORKING_DIR'], config_name), 'w') as output:
            output.write(cfg_rendered)


def run_daemon(program_config):
    """Start binary and return its process object"""
    name = program_config['DAEMON_NAME']
    proc = None
    program_config['log'] = os.path.join(program_config["WORKING_DIR"], 'server.log')
    daemon_log_file = open(program_config['log'], 'w')
    program_config['args'] = [program_config['binary']] + program_config['additional']
    logging.getLogger('deckard.daemon.%s.argv' % name).debug('%s', program_config['args'])
    try:
        proc = subprocess.Popen(program_config['args'], stdout=daemon_log_file, stderr=subprocess.STDOUT,
                                cwd=program_config['WORKING_DIR'], start_new_session=True)
    except subprocess.CalledProcessError:
        logger = logging.getLogger('deckard.daemon_log.%s' % name)
        logger.exception("Can't start '%s'", program_config['args'])
        raise
    return proc


def conncheck_daemon(process, cfg, sockfamily):
    """Wait until the server accepts TCP clients"""
    sock = socket.socket(sockfamily, socket.SOCK_STREAM)
    tstart = datetime.now()
    while True:
        time.sleep(0.1)
        if (datetime.now() - tstart).total_seconds() > 5:
            raise RuntimeError("Server took too long to respond")
        # Check if the process is running
        if process.poll() is not None:
            msg = 'process died "%s", logs in "%s"' % (cfg['name'], cfg['WORKING_DIR'])
            logger = logging.getLogger('deckard.daemon_log.%s' % cfg['name'])
            logger.critical(msg)
            logger.error(open(cfg['log']).read())
            raise subprocess.CalledProcessError(process.returncode, cfg['args'], msg)
        try:
            sock.connect((cfg['address'], 53))
        except socket.error:
            continue
        break
    sock.close()


def setup_daemons(config):
    """Configure daemons and start them"""
    # Setup daemon environment
    daemons = []

    for program_config in config['programs']:
        setup_daemon_environment(program_config, config)
        generate_from_templates(program_config, config)

        daemon_proc = run_daemon(program_config)
        daemons.append({'proc': daemon_proc, 'cfg': program_config})
        try:
            conncheck_daemon(daemon_proc, program_config, config['_SOCKET_FAMILY'])
        except:  # noqa  -- bare except might be valid here?
            daemon_proc.terminate()
            raise

    return daemons


def check_for_reply_steps(case: scenario.Scenario) -> bool:
    return any(s.type == "REPLY" for s in case.steps)


def run_testcase(case, daemons, config, prog_under_test_ip):
    """Run actual test and raise exception if the test failed"""
    server = testserver.TestServer(case, config["ROOT_ADDR"], config["_SOCKET_FAMILY"], config["DECKARD_IP"], config["if_manager"])
    server.start()

    try:
        server.play(prog_under_test_ip)
    finally:
        server.stop()

        if check_for_reply_steps(case):
            logging.warning("%s has REPLY steps in it. These are known to fail randomly. "
                            "Errors might be false positives.", case.file)

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

    if server.undefined_answers > 0:
        raise ValueError('the scenario does not define all necessary answers (see error log)')


def process_file(path, qmin, config):
    """Parse scenario from a file object and create workdir."""
    # Parse scenario
    case, case_config_text = scenario.parse_file(os.path.realpath(path))
    case_config = scenario.parse_config(case_config_text, qmin, INSTALLDIR)

    # Merge global and scenario configs
    config.update(case_config)

    # Asign addresses to the programs and Deckard itself
    setup_internal_addresses(config)

    # Deckard will communicate with first program
    prog_under_test = config['programs'][0]['name']
    prog_under_test_ip = config['programs'][0]['address']

    setup_faketime(config)

    # Copy the scenario to tmpdir for future reference
    shutil.copy2(path, os.path.join(config["tmpdir"]))

    try:
        daemons = setup_daemons(config)
        run_testcase(case, daemons, config, prog_under_test_ip)

    except Exception:
        logging.getLogger('deckard.hint').error(
            'test failed, inspect working directory %s', config["tmpdir"])
        raise
