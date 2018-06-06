from os import chdir
from json import load
from re import compile
from socket import gethostbyname
from yangson import DataModel
from pathlib import Path
from colorlog import warning, info

ip_addr_re = compile('^((\d{1,3}\.){3}\d{1,3})|(([\dA-Fa-f]{1,4})|(:)|(:[\dA-Fa-f]{1,4})){2,7}[\dA-Fa-f]$')


class ScenarioGenerator:
    def __init__(self, model: DataModel):

        # default paths where to create files and names
        self.unbound_path = str(Path.home()) + "/unbound.rpl"
        self.kresd_path = str(Path.home()) + "/kresd.rpl"

        self.data_model = model     # type: DataModel
        self.conf_data = {}         # type: str
        self.mock_path = ""         # type: str

    def load_file(self, path: str):

        global ri
        try:
            with open(path) as infile:
                ri = load(infile)
        except IOError:
            error("Failed to load json file: \"{}\"" .format(path))

        data = self.data_model.from_raw(ri)

        data.validate()

        # creating data with missing default values
        data_defaults = data.add_defaults()

        data_defaults = data_defaults["cznic-resolver-common:dns-resolver"]

        self.mock_path = data["cznic-deckard:deckard"]["mock-data"].value

        self.conf_data = self.sort_data(data_defaults)

    @staticmethod
    def sort_data(data: str):
        context = {'network': 1,
                   'server': 2,
                   'resolver': 3,
                   'logging': 4,
                   'dnssec': 5,
                   'cache': 6,
                   'dns64': 7}

        # sort data
        sorted_data = [data[i] for i in sorted(data, key=context.__getitem__)]

        return sorted_data

    def write_scenario(self):

        unb_file = open(self.unbound_path, "w+")
        unb_scenario = self.gen_unb_scenario()
        unb_file.write(unb_scenario)
        unb_file.close()

        knot_file = open(self.kresd_path, "w+")
        knot_conf = self.gen_kresd()
        knot_file.write(knot_conf)
        knot_file.close()

    def gen_unb_scenario(self):
        unb_conf = self.gen_unbound()
        mock = open(self.mock_path).read()

        scenario = unb_conf + mock
        return scenario

    ############################ UNBOUND CONF GENERATOR ############################
    # Function for generate Unbound configuration file
    def gen_unbound(self):
        # Create clear configuration file
        unb_conf_string = "; config options\n"
        server = "server:\n"
        stub = ""

        for item in self.conf_data:

            ############ SERVER ############
            if item.name == 'server':
                # user-name
                if 'user-name' in item:
                    server += str("\tusername: \"{}\"\n".format(item['user-name'].value))

                # group-name
                if 'group-name' in item:
                    pass

            ############ NETWORK ############
            if item.name == 'network':
                # listen-interfaces
                if 'listen-interfaces' in item:
                    for interface in item['listen-interfaces']:
                        temp = ""
                        # name
                        if 'name' in interface:
                            pass
                        # ip-address
                        if 'ip-address' in interface:
                            temp = str(interface["ip-address"])
                        # port
                        if 'port' in interface:
                            temp = temp + "@" + str(interface["port"])
                        server += str("\tinterface: {}\n".format(temp))

                # client-transport
                if 'client-transport' in item:
                    # l2-protocols
                    '''
                    if 'l2-protocols' in item['client-transport']:
                        if str(item['client-transport']['l2-protocols']) == "ipv6":
                            server += str("\tdo-ip6 = yes\n\tdo-ip4 = no\n")
                        elif str(item['client-transport']['l2-protocols']) == "ipv4":
                            server += str("\tdo-ip6 = no\n\tdo-ip4 = yes\n")
                        else:
                            server += str("\tdo-ip6 = yes\n\tdo-ip4 = yes\n")
                    '''

                # recursion-transport
                if 'recursion-transport' in item:
                    # l2-protocols
                    if 'l2-protocols' in item['recursion-transport']:
                        protocols = str(item['recursion-transport']['l2-protocols'].value)

                        if 'ipv4' in protocols:
                            if 'ipv6' in protocols:
                                server += str("\tdo-ip6 = yes\n\tdo-ip4 = yes\n")
                            else:
                                server += str("\tdo-ip6 = no\n\tdo-ip4 = yes\n")
                        else:
                            if 'ipv6' in protocols:
                                server += str("\tdo-ip6 = yes\n\tdo-ip4 = no\n")
                            else:
                                server += str("\tdo-ip6 = no\n\tdo-ip4 = no\n")

            ############ RESOLVER ############
            if item.name == 'resolver':
                # stub-zones
                if 'stub-zones' in item:

                    for sz in item['stub-zones']:

                        stub += "\nstub-zone:\n"
                        temp = "::"

                        # domain
                        if 'domain' in sz:
                            stub += str("\tname: \"{}\"\n".format(sz["domain"]))
                            '''
                            temp = str(sz["domain"])

                            # port
                            if 'port' in sz:
                                temp += "@" + str(sz["port"])

                            if ipaddr_re.match(str(sz["domain"])):
                                stub += str("\tstub-addr: \"{}\"\n" .format(temp))
                            else:
                                stub += str("\tstub-host: \"{}\"\n" .format(temp))
                                '''
                        # nameserver
                        if 'nameserver' in sz:
                            temp = str(sz["nameserver"])

                            # port
                            if 'port' in sz:
                                temp += "@" + str(sz["port"])

                        if ip_addr_re.match(str(sz["nameserver"])):
                            stub += str("\tstub-addr: \"{}\"\n".format(temp))
                        else:
                            stub += str("\tstub-host: \"{}\"\n".format(temp))

                # options
                if 'options' in item:
                    # glue-checking
                    if 'glue-checking' in item['options']:
                        if str(item['options']['glue-checking'].value) == "strict":
                            server += str("\tharden-glue: yes\n")
                        else:
                            server += str("\tharden-glue: no\n")

                    # qname-minimisation
                    if 'qname-minimisation' in item['options']:
                        if item['options']['qname-minimisation'].value:
                            server += str("\tqname-minimisation: yes\n")
                        else:
                            server += str("\tqname-minimisation: no\n")

                    # query-loopback
                    if 'query-loopback' in item['options']:
                        if item['options']['query-loopback'].value:
                            server += str("\tdo-not-query-localhost: no\n")
                        else:
                            server += str("\tdo-not-query-localhost: yes\n")

            # logging/verbosity
            if item.name == 'logging':
                if 'verbosity' in item:
                    server += str("\tverbosity: {}\n".format(item['verbosity'].value))

            ############ DNSSEC ############
            if item.name == 'dnssec':
                # trust-anchors
                if 'trust-anchors' in item:
                    # key-files
                    if 'key-files' in item['trust-anchors']:
                        for kf in item['trust-anchors']['key-files']:
                            # domain
                            if 'domain' in kf:
                                pass
                                # file
                            if 'file' in kf:
                                server += str("\tauto-trust-anchor-file: \"{}\"\n".format(kf['file']))
                            # read-only
                            if 'read-only' in kf:
                                pass

                # negative-trust-anchors
                if 'negative-trust-anchors' in item:
                    for nta in item['negative-trust-anchors']:
                        server += str("\tdomain-insecure: \"{}\"\n".format(nta))

            ############# CACHE ############
            if item.name == 'cache':
                # max-size
                if 'max-size' in item:
                    server += str("\tmsg-cache-size: {}\n".format(item['max-size'].value))

                # max-ttl
                if 'max-ttl' in item:
                    server += str("\tcache-max-ttl: {}\n".format(item['max-ttl'].value))
                # min-ttl
                if 'min-ttl' in item:
                    server += str("\tcache-min-ttl: {}\n".format(item['min-ttl'].value))

            # dns64/prefix
            if item.name == 'dns64':
                if 'prefix' in item:
                    server += str("\tdns64-prefix: {}\n".format(item['prefix'].value))

        unb_conf_string += server + stub

        return unb_conf_string

    ############################ KNOT CONF GENERATOR ############################
    # Function for generate Knot configuration file
    def gen_kresd(self):
        # Create clear configuration file
        conf_string = "; config options\n"

        for item in self.conf_data:

            ############ SERVER ############
            if item.name == 'server':
                # user-name
                if 'user-name' in item:

                    # group-name
                    if 'group-name' in item:
                        conf_string += str("user('{0}','{1}')\n".format(item['user-name'].value,
                                                                        item['group-name'].value))
                    else:
                        conf_string += str("user('{0}','')\n".format(item['user-name'].value))

            ############ NETWORK ############
            if item.name == 'network':
                # listen-interfaces
                if 'listen-interfaces' in item:
                    interfaces = []
                    for interface in item['listen-interfaces']:
                        temp = ""
                        # name
                        if 'name' in interface:
                            pass
                        # ip-address
                        if 'ip-address' in interface:
                            temp = str(interface["ip-address"])
                        # port
                        if 'port' in interface:
                            temp += "@" + str(interface["port"])

                        interfaces.append(temp)

                    conf_string += str("net = {" + str(interfaces)[1:-1] + "}\n")

                # client-transport
                if 'client-transport' in item:
                    # l2-protocols
                    pass

                # recursion-transport
                if 'recursion-transport' in item:
                    # l2-protocols
                    protocols = str(item['recursion-transport']['l2-protocols'])
                    if 'ipv4' in protocols:
                        if 'ipv6' in protocols:
                            conf_string += "net.ipv6 = true\nnet.ipv4 = true\n"
                        else:
                            conf_string += "net.ipv6 = false\nnet.ipv4 = true\n"
                    else:
                        if 'ipv6' in protocols:
                            conf_string += "net.ipv6 = true\nnet.ipv4 = false\n"
                        else:
                            conf_string += "net.ipv6 = false\nnet.ipv4 = false\n"

            ############ RESOLVER ############
            if item.name == 'resolver':
                # stub-zones
                if 'stub-zones' in item:
                    stub_addr = []
                    for sz in item['stub-zones']:
                        temp = "::"
                        # domain
                        if 'domain' in sz:
                            '''
                            if ipaddr_re.match(str(sz["domain"])):
                                try:
                                    ip_addr = gethostbyname_ex(str(sz["domain"]))
                                    temp = repr(ip_addr)
                                except ValueError:
                                    print("Knot Generator error: failed to resolve domain to address")

                            else:
                                temp = str(sz["domain"])
                                '''
                        # nameserver
                        if 'nameserver' in sz:

                            # port
                            if 'port' in sz:
                                temp = "@" + str(sz["port"])

                            if ip_addr_re.match(str(sz["nameserver"])):
                                temp = str(sz["nameserver"]) + temp
                                stub_addr.append(temp)

                            else:
                                try:
                                    temp = gethostbyname(str(sz["nameserver"])) + temp
                                    stub_addr.append(temp)

                                except OSError:
                                    warning(" Knot generator: stub-zone/nameserver\n"
                                            "Failed to resolve domain-name "
                                            "({0}) to ip address ".format(str(sz["nameserver"])))

                    if stub_addr:
                        conf_string += "STUB(" + str(stub_addr)[1:-1] + ")\n"

                # options
                if 'options' in item:
                    # glue-checking
                    if 'glue-checking' in item['options']:
                        conf_string += str("mode('{}')\n".format(item['options']['glue-checking'].value))
                    # qname-minimisation
                    if 'qname-minimisation' in item['options']:
                        if item['options']['qname-minimisation'].value:
                            conf_string += "option('NO_MINIMIZE', false)\n"
                        else:
                            conf_string += "option('NO_MINIMIZE', true)\n"

                    # query-loopback
                    if 'query-loopback' in item['options']:
                        if item['options']['query-loopback'].value:
                            conf_string += "option('ALLOW_LOCAL', true)\n"
                        else:
                            conf_string += "option('ALLOW_LOCAL', false)\n"

            ############ logging/verbosity ############
            if item.name == 'logging':
                if 'verbosity' in item:
                    if item['verbosity'].value == 0:
                        conf_string += "verbose(false)\n"
                    else:
                        conf_string += "verbose(true)\n"

            ############ DNSSEC ############
            if item.name == 'dnssec':
                # trust-anchors
                if 'trust-anchors' in item:
                    # key-files
                    if 'key-files' in item['trust-anchors']:
                        for kf in item['trust-anchors']['key-files']:
                            # domain
                            if 'domain' in kf:
                                pass
                                # file
                            if 'file' in kf:

                                # read-only
                                if 'read-only' in kf:
                                    conf_string += str("trust_anchors.add_file('{0}',{1})\n".format(kf['file'],
                                                                                                    kf['read-only']))

                                else:
                                    conf_string += str("trust_anchors.add_file('{0}')\n".format(kf['file']))

                # negative-trust-anchors
                if 'negative-trust-anchors' in item:
                    insecure = []
                    for nta in item['negative-trust-anchors']:
                        insecure.append(nta.value)

                    conf_string += str("trust_anchors.set_insecure({" + str(insecure)[1:-1]) + "})\n"

            ############# CACHE ############
            if item.name == 'cache':
                # max-size
                if 'max-size' in item:
                    conf_string += str("cache.size = {}\n".format(item['max-size'].value))

                # max-ttl
                if 'max-ttl' in item:
                    conf_string += str("cache.max_ttl({})\n".format(item['max-ttl'].value))
                # min-ttl
                if 'min-ttl' in item:
                    conf_string += str("cache.min_ttl({})\n".format(item['min-ttl'].value))

            ############ dns64/prefix ############
            if item.name == 'dns64':
                if 'prefix' in item:
                    conf_string += str("modules.load('dns64')\ndns64.config('{}')\n".format(item['prefix'].value))

        return conf_string



