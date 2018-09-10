import sys
from yangson.datamodel import DataModel
from json import load
from resolvers_yang.generator import gen_unbound, gen_kresd

json_path = sys.argv[1]

# set file names and paths
yangdir = "yang-modules"
kresd_path = "kresd.conf"
unb_path = "unbound.rpl"

# load model
model = DataModel.from_file(yangdir + "/yanglib-deckard.json", [yangdir])

# load data from json
with open(json_path) as infile:
    ri = load(infile)

data = model.from_raw(ri)

# validate against data model
data.validate()

# get path where is mock data located
mock_path = data["cznic-deckard:deckard"]["mock-data"].value

# load mock data text file from path as string
mock_data = open(mock_path).read()

# slicing mock_data
mock_begin = mock_data.find("SCENARIO_BEGIN")
mock_data = mock_data[mock_begin:]

# generate configuration strings
unb_conf = gen_unbound(data)
kresd_conf = gen_kresd(data)

# write kresd.conf
knot_file = open(kresd_path, "w+")
knot_file.write(kresd_conf)
knot_file.close()

# write unbound.rpl = unbconf string + mock data
unb_file = open(unb_path, "w+")
unb_file.write(unb_conf + "\nCONFIG_END\n\n" + mock_data)
unb_file.close()
