from collections import namedtuple
import glob
import os
import re
import yaml


Scenario = namedtuple("Scenario", ["path", "qmin", "config"])


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


def scenarios(paths, configs):
    """Returns list of *.rpl files from given path and packs them with their minimization setting"""

    assert len(paths) == len(configs),\
        "Number of --config has to be equal to number of --scenarios arguments."

    scenario_list = []

    for path, config in zip(paths, configs):
        config_dict = yaml.safe_load(open(config))
        config_sanity_check(config_dict, config)

        if os.path.isfile(path):
            filelist = [path]  # path to single file, accept it
        else:
            filelist = sorted(glob.glob(os.path.join(path, "*.rpl")))

        if not filelist:
            raise ValueError('no *.rpl files found in path "{}"'.format(path))

        for file in filelist:
            scenario_list.append(Scenario(file, get_qmin_config(file), config_dict))

    return scenario_list


def pytest_addoption(parser):
    parser.addoption("--config", action="append", help="path to Deckard configuration .yaml file")
    parser.addoption("--scenarios", action="append", help="directory with .rpl files")


def pytest_generate_tests(metafunc):
    """This is pytest weirdness to parametrize the test over all the *.rpl files."""
    if 'scenario' in metafunc.fixturenames:
        if metafunc.config.option.config is None:
            configs = []
        else:
            configs = metafunc.config.option.config

        if metafunc.config.option.scenarios is None:
            paths = ["sets/resolver"] * len(configs)
        else:
            paths = metafunc.config.option.scenarios

        metafunc.parametrize("scenario", scenarios(paths, configs), ids=str)
