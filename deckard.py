#!/usr/bin/env python3
import errno
import logging
import logging.config
import os
import shlex
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


def setup_internal_addresses(context):
    context["DECKARD_IP"] = context["if_manager"].assign_internal_address(context["_SOCKET_FAMILY"])
    for program in context["programs"]:
        program["address"] = context["if_manager"].assign_internal_address(
            context["_SOCKET_FAMILY"])


def write_timestamp_file(path, tst):
    with open(path, 'w', encoding='utf-8') as time_file:
        time_file.write(datetime.fromtimestamp(tst).strftime('@%Y-%m-%d %H:%M:%S'))


def setup_faketime(context):
    """
    Setup environment shared between Deckard and binaries under test.

    Environment for child processes must be based on on.environ as modified
    by this function.
    """
    # Set up libfaketime
    os.environ["FAKETIME_NO_CACHE"] = "1"
    os.environ["FAKETIME_TIMESTAMP_FILE"] = os.path.join(context["tmpdir"], ".time")
    os.unsetenv("FAKETIME")

    write_timestamp_file(os.environ["FAKETIME_TIMESTAMP_FILE"],
                         context.get('_OVERRIDE_TIMESTAMP', time.time()))


def setup_daemon_environment(program_config, context):
    program_config["WORKING_DIR"] = os.path.join(context["tmpdir"], program_config["name"])
    os.mkdir(program_config['WORKING_DIR'])
    program_config["DAEMON_NAME"] = program_config["name"]
    program_config['SELF_ADDR'] = program_config['address']
    program_config['TRUST_ANCHOR_FILES'] = create_trust_anchor_files(
        context["TRUST_ANCHOR_FILES"], program_config['WORKING_DIR'])


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
        file_name = f'{domain}.key'
        full_path = os.path.realpath(
            os.path.join(work_dir, TRUST_ANCHOR_SUBDIR, file_name))
        full_paths.append(full_path)
        dir_path = os.path.dirname(full_path)
        try:
            os.makedirs(dir_path)
        except OSError as ex:
            if ex.errno != errno.EEXIST:
                raise
        with open(full_path, "w", encoding="utf-8") as ta_file:
            ta_file.writelines(f'{line}\n' for line in ta_lines)
    return full_paths


def generate_from_templates(program_config, context):
    """Generate configuration for the program"""
    template_ctx = context.copy()
    template_ctx.update(program_config)

    # public mapping program name -> program vars
    template_ctx['PROGRAMS'] = {}
    for cfg in template_ctx['programs']:
        template_ctx['PROGRAMS'][cfg['name']] = cfg

    j2template_loader = jinja2.FileSystemLoader(searchpath=os.getcwd())
    j2template_env = jinja2.Environment(loader=j2template_loader)

    for template_name, config_name in zip(template_ctx['templates'], template_ctx['configs']):
        j2template = j2template_env.get_template(template_name)
        cfg_rendered = j2template.render(template_ctx)
        config_path = os.path.join(template_ctx['WORKING_DIR'], config_name)
        with open(config_path, 'w', encoding='utf-8') as output:
            output.write(cfg_rendered)


def run_daemon(program_config):
    """Start binary and return its process object"""
    name = program_config['DAEMON_NAME']
    proc = None
    program_config['log'] = os.path.join(program_config["WORKING_DIR"], 'server.log')
    program_config['args'] = (
        shlex.split(os.environ.get('DECKARD_WRAPPER', ''))
        + [program_config['binary']]
        + program_config['additional']
    )
    logging.getLogger(f'deckard.daemon.{name}.argv').debug('%s', program_config['args'])
    with open(program_config['log'], 'w', encoding='utf-8') as daemon_log_file:
        try:
            # pylint: disable=consider-using-with
            proc = subprocess.Popen(program_config['args'], stdout=daemon_log_file,
                                    stderr=subprocess.STDOUT, cwd=program_config['WORKING_DIR'])
        except subprocess.CalledProcessError:
            logger = logging.getLogger(f'deckard.daemon_log.{name}')
            logger.exception("Can't start '%s'", program_config['args'])
            raise
    return proc


def log_fatal_daemon_error(cfg, msg):
    logger = logging.getLogger(f'deckard.daemon_log.{cfg["name"]}')
    logger.critical(msg)
    logger.critical('logs are in "%s"', cfg['WORKING_DIR'])
    with open(cfg['log'], encoding='utf-8') as logfile:
        logger.error('daemon log follows:')
        logger.error(logfile.read())


def conncheck_daemon(process, cfg, sockfamily):
    """Wait until the server accepts TCP clients"""
    sock = socket.socket(sockfamily, socket.SOCK_STREAM)
    deadline = time.monotonic() + 5
    with sock:
        while True:
            # Check if the process is running
            ecode = process.poll()
            if ecode is not None:
                msg = f'process died, exit code {ecode}'
                log_fatal_daemon_error(cfg, msg)
                raise subprocess.CalledProcessError(process.returncode, cfg['args'], msg)
            try:
                sock.connect((cfg['address'], 53))
                return  # success
            except socket.error as ex:
                if time.monotonic() > deadline:
                    msg = 'server does not accept connections on TCP port 53'
                    log_fatal_daemon_error(cfg, msg)
                    raise DeckardUnderLoadError(msg) from ex

            time.sleep(0.1)


def setup_daemons(context):
    """Configure daemons and start them"""
    # Setup daemon environment
    daemons = []

    for program_config in context['programs']:
        setup_daemon_environment(program_config, context)
        generate_from_templates(program_config, context)

        daemon_proc = run_daemon(program_config)
        daemons.append({'proc': daemon_proc, 'cfg': program_config})
        if program_config.get('conncheck', True):
            try:
                conncheck_daemon(daemon_proc, program_config, context['_SOCKET_FAMILY'])
            except:  # noqa  -- bare except might be valid here?
                daemon_proc.terminate()
                raise

    return daemons


def check_for_reply_steps(case: scenario.Scenario) -> bool:
    return any(s.type == "REPLY" for s in case.steps)


def run_testcase(case, daemons, context, prog_under_test_ip):
    """Run actual test and raise exception if the test failed"""
    server = testserver.TestServer(case, context["_SOCKET_FAMILY"],
                                   context["DECKARD_IP"], context["if_manager"])
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
            daemon_logger_log = logging.getLogger(f'deckard.daemon_log.{daemon["cfg"]["name"]}')
            with open(daemon['cfg']['log'], encoding='utf-8') as logf:
                for line in logf:
                    daemon_logger_log.debug(line.strip())
            ignore_exit = daemon["cfg"].get('ignore_exit_code', False)
            if daemon['proc'].returncode != 0 and not ignore_exit:
                raise ValueError(f"process {daemon['cfg']['name']} terminated "
                                 f"with return code {daemon['proc'].returncode}")

    if server.undefined_answers > 0:
        raise ValueError('the scenario does not define all necessary answers (see error log)')


def process_file(path, qmin, config):
    """Parse scenario from a file object and create workdir."""

    # Preserve original configuration
    context = config.copy()

    # Parse scenario
    case, case_config_text = scenario.parse_file(os.path.realpath(path))
    case_config = scenario.parse_config(case_config_text, qmin, INSTALLDIR)

    # Merge global and scenario configs
    context.update(case_config)

    # Asign addresses to the programs and Deckard itself
    setup_internal_addresses(context)

    # Deckard will communicate with first program
    prog_under_test_ip = context['programs'][0]['address']

    setup_faketime(context)

    # Copy the scenario to tmpdir for future reference
    shutil.copy2(path, os.path.join(context["tmpdir"]))

    try:
        daemons = setup_daemons(context)
        run_testcase(case, daemons, context, prog_under_test_ip)

    except Exception:
        logging.getLogger('deckard.hint').error(
            'test failed, inspect working directory %s', context["tmpdir"])
        raise
