import sys
from yangson import DataModel

from generator import ScenarioGenerator

yangdir = "yang-modules"

model = DataModel.from_file(yangdir + "/yang-library-data.json", [yangdir])
path = sys.argv[1]

# create configuration generator for specific data model
generator = ScenarioGenerator(model)

# load, validate and sort data from file
generator.load_file(path)

generator.unbound_path = str("unb.rpl")
generator.kresd_path = str("kresd.rpl")

# generate and write set for deckard
generator.write_scenario()
