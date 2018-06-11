import sys
import os
from yangson import DataModel
from json import load

import urllib.request
url = 'https://gitlab.labs.nic.cz/jetconf/jetconf-resolver/raw/master/jetconf_resolver/conf_generator.py'
urllib.request.urlretrieve(url, 'generator_tmp.py')
from generator_tmp import ConfGenerator

# set name and paths for .rpl files
unb_path = str("unb.rpl")
kresd_path = str("kresd.rpl")

yangdir = "yang-modules"
data_model = DataModel.from_file(yangdir + "/yang-library-data.json", [yangdir])
json_path = sys.argv[1]


class DeckardConf(ConfGenerator):
    def __init__(self, model: DataModel):
        super().__init__(model)
        self.mock_path = ""  # type: str

    def write(self, file_path: str, data: str):
        file = open(file_path, "w+")
        file.write(data)
        file.close()

    def write_files(self):
        mock_data = open(self.mock_path).read()
        unbound = self.generate_unbound() + mock_data
        # write unbound
        self.write(self.unbound_path, unbound)

        # write kresd
        kresd = self.generate_knot()
        self.write(self.kresd_path, kresd)

    def load_file(self, path: str):

        with open(path) as infile:
            ri = load(infile)

        data = self.data_model.from_raw(ri)

        data.validate()

        # creating data with missing default values
        data_defaults = data.add_defaults()

        data_defaults = data_defaults["cznic-resolver-common:dns-resolver"]

        self.conf_data = self.sort_data(data_defaults)

        self.mock_path = data["cznic-deckard:deckard"]["mock-data"].value


if __name__ == "__main__":

    # create configuration generator for specific data model
    generator = DeckardConf(data_model)
    # load, validate and sort data from file
    generator.load_file(json_path)

    # set paths where to save .rpl files
    generator.unbound_path = unb_path
    generator.kresd_path = kresd_path

    # generate and write set for deckard
    generator.write_files()

    # remove downloaded file
    os.remove('generator_tmp.py')
