from collections import namedtuple
import glob
import os
import pytest
import re
import yaml


Scenario = namedtuple("Scenario", ["path", "qmin"])


def config_sanity_check(config_dict, config_name):
    """Checks if parsed configuration is valid"""
    mandatory_keys = {'name', 'binary', 'templates', 'configs', 'additional'}
    for cfg in config_dict['programs']:
        missing_keys = mandatory_keys - set(cfg.keys())
        assert not missing_keys, 'Mandatory fields in configuration are missing: %s' % missing_keys

        # sanity check templates vs. configs
        assert len(cfg['templates']) == len(cfg['configs']),\
            ('Number of jinja2 template files is not equal '
             'to number of config files to be generated for '
             'program "%s" (%s), i.e. len(templates) != len(configs)'
             % (cfg['name'], config_name))

        for additional in cfg["additional"]:
            assert type(additional) is str,\
                "All additional arguments in yaml should be strings. (%s, %s)"\
                % (cfg['name'], config_name)


def get_qmin_config(path):
    """Reads configuration from the *.rpl file and determines query-minimization setting."""
    with open(path) as f:
        for line in f:
            if re.search(r"^CONFIG_END", line) or re.search(r"^SCENARIO_BEGIN", line):
                return None
            if re.search(r"^\s*query-minimization:\s*(on|yes)", line):
                return True
            if re.search(r"^\s*query-minimization:\s*(off|no)", line):
                return False


def scenarios(scenarios_path):
    """Returns list of *.rpl files from given path and packs them with their minimization setting"""
    return [Scenario(scenario, get_qmin_config(scenario))
            for scenario in sorted(glob.glob(os.path.join(scenarios_path, "*.rpl")))]


def pytest_addoption(parser):
    parser.addoption("--config", action="store")
    parser.addoption("--scenarios", action="store")


def pytest_generate_tests(metafunc):
    """This is pytest weirdness to parametrize the test over all the *.rpl files."""
    if 'scenario' in metafunc.fixturenames:
        if metafunc.config.option.scenarios is not None:
            paths = metafunc.config.option.scenarios
            metafunc.parametrize("scenario", scenarios(paths[0]), ids=str)
        else:
            # If no --config option is given, we use the default from Deckard repository
            metafunc.parametrize("scenario", scenarios("sets/resolver"), ids=str)


@pytest.fixture
def config(request):
    """Parses and checks the config given"""
    config_file = request.config.getoption("--config")
    configuration = yaml.safe_load(open(config_file))
    config_sanity_check(configuration, config_file)
    return configuration
