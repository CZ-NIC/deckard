Deckard
=======


**Introduction**

Deckard is intended for dns software testing in your own environment to show 
that it has desired behavior. Main part of the project is the python script. 
Script runs given binary as a subprocess, then sends him some prescripted queries, 
compares answers with referenced data and decides whether test is successful or not. 
At the moment only UDP transport is supported. All network communications are 
redirected over UNIX sockets, so you don't need to get test network because dns 
binaries runs locally at a kind of sandbox. When it is required by testing context, 
dns binary can be forced to get faked system time. Test process flowing is guided 
by scenario. Scenario is a simple text-based file, which contains queries, expected 
answers and additional data. Also is possible to include raw dns packets in it.

**Requirements**

Deckard requires next software to be installed :

- Python (tested on Python 2.7)
- `DNS toolkit`_ for Python
- Jinja2_ template engine for Python
- `socket wrapper`_ library

also it depends on

- Libfaketime_ library; the libfaketime is included in ``contrib/libfaketime`` 
  as it depends on rather latest version of it, it is automatically synchronised 
  with ``make``

**Compatibility**

Project has been tested with `Knot DNS Resolver`_ on Linux and MacOS
and `PowerDNS Recursor`_ on Linux only.

**Usage**

Using of Deckard consists of :

a) **Setting up socket wrapper library (cwrap)**

Detailed instructions on using cwrap you can read here_

Generally, explicit environment setup for cwrap is not required. 
When cwrap environment is absent, default values will be used :

- **SOCKET_WRAPPER_DEFAULT_IFACE** = 10
- **SOCKET_WRAPPER_DIR** will be created in default temporary directory with 
  randomly generated name, prefixed by tmp
- **SOCKET_WRAPPER_DEBUGLEVEL** will not be set

**SOCKET_WRAPPER_DIR** also used as work directory for binary under test. When test 
failed, work directory can contain useful information to analyze. For debugging 
purposes sometimes might be better to use well-known location rather then 
temporary directory with randomly generated name. In this case you can explicitly
set **SOCKET_WRAPPER_DIR** to any eligible value.

b) **Writing your own scenario**

See `scenario guide`_
    
c) **Setting up configuration for binary, intended to test.**

Generally server software can be configured by using configuration file. 
It is a very convenient way, but in our case some configuration values can be 
only known after the test started. To resolve this problem jinja2 templating 
engine is used. You can prepare jinja2 template of configuration file. It will 
be processed before test really started, then actual configuration file 
will be generated at working dir.

You can use next template variables:

- **ROOT_ADDR**    - address of root server. It is a IP4 address looks like 127.0.0.XXX,
  where XXX is **SOCKET_WRAPPER_DEFAULT_IFACE** environment variable value. It must 
  be used as a entry of root hints list. When root hints resides in separated file, 
  this file must be edited manually. Port is not set and assumed to be equal to 53.
- **SELF_ADDR**    - address, to which binary under test must be bounded. It is a IP4 
  address looks like 127.0.0.XXX, where XXX is **KRESD_WRAPPER_DEFAULT_IFACE** value. 
  Port is not set and assumed to be equal to 53.
- **NO_MINIMIZE**  - 'true' of 'false', enables or disables query minimization respectively.
- **WORKING_DIR**  - working directory, it is a value of **SOCKET_WRAPPER_DIR**
  environment variable.

d) **Setting up your environment**

You can alter test process flow by using next environment variables :

- **TESTS**        - path to scenario files; default value is **sets/resolver**
- **DAEMON**       - path to binary have to be tested; default value is **kresd**
- **TEMPLATE**     - jinja2 template file to generate configuration file; default value is **kresd.j2**
- **CONFIG**       - name of configuration file to be generated; default value is **config**
- **ADDITIONAL**   - additional parameters for binary, intended to test; not set by default

Note, that default values intended to be used with Knot DNS Resolver.

Also, **KRESD_WRAPPER_DEFAULT_IFACE** environment variable is used to set up default socket 
wrapper interface for the binary under test. If not set explicitly, this default value will 
be used : **KRESD_WRAPPER_DEFAULT_IFACE** = **SOCKET_WRAPPER_DEFAULT_IFACE** + 1.
Generally there are no reasons to set up this value explicitly, except better readability 
of configuration script.

e) **Running.**

Execute the tests by running **make** utility.

.. code-block:: bash

    make TESTS=sets/resolver DAEMON=/usr/local/bin/kresd TEMPLATE=kresd.j2 CONFIG=config

As said above, default values are set for using with Knot DNS resolver.
If Knot DNS resolver is properly installed, you should not set any parameters.

Below is a example of script, which explicitly sets environment variables and 
runs tests for Knot DNS Resolver daemon.

.. code-block:: bash

    #!/bin/bash

    # Path to scenario files
    TESTS=sets/resolver 

    # Path to daemon
    DAEMON=/usr/local/bin/kresd
     
    # Template file name
    TEMPLATE=kresd.j2 

    # Config file name
    CONFIG=config

    export TESTS DAEMON TEMPLATE CONFIG

    make


configuration template example
::

    net.listen('{{SELF_ADDR}}',53)
    cache.size = 1*MB
    modules = {'stats', 'block', 'hints'}
    hints.root({['k.root-servers.net'] = '{{ROOT_ADDR}}'})
    option('NO_MINIMIZE', {{NO_MINIMIZE}})
    option('ALLOW_LOCAL', true)

    -- Self-checks on globals
    assert(help() ~= nil)
    assert(worker.id ~= nil)
    -- Self-checks on facilities
    assert(cache.count() == 0)
    assert(cache.stats() ~= nil)
    assert(cache.backends() ~= nil)
    assert(worker.stats() ~= nil)
    assert(net.interfaces() ~= nil)
    -- Self-checks on loaded stuff
    assert(net.list()['{{SELF_ADDR}}'])
    assert(#modules.list() > 0)
    -- Self-check timers
    ev = event.recurrent(1 * sec, function (ev) return 1 end)
    event.cancel(ev)
    ev = event.after(0, function (ev) return 1 end)

Below is a example of script, which tests Power DNS Recursor

.. code-block:: bash

    #!/bin/bash

    # Path to scenario files
    TESTS=sets/resolver 

    # Path to daemon
    DAEMON=pdns_recursor
     
    # Template file name
    TEMPLATE=recursor.j2 

    # Config file name
    CONFIG=recursor.conf
    
    # Additional parameter for pdns_recursor
    # it means that configuration file can be found in working directory
    ADDITIONAL=--config-dir=./

    export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL

    make

configuration template example, shown only changed lines of original recursor.conf
::

    ...
    
    #################################
    # config-dir	Location of configuration directory (recursor.conf)
    #
    config-dir={{WORKING_DIR}}
    
    ...

    #################################
    # local-address	IP addresses to listen on, separated by spaces or commas. Also accepts ports.
    #
    local-address={{SELF_ADDR}}

    ...
    
    #################################
    # socket-dir	Where the controlsocket will live
    #
    socket-dir={{WORKING_DIR}}

    ...

.. _`DNS toolkit`: http://www.dnspython.org/
.. _Jinja2: http://jinja.pocoo.org/
.. _`socket wrapper`: https://cwrap.org/socket_wrapper.html
.. _Libfaketime: https://github.com/wolfcw/libfaketime
.. _`Knot DNS Resolver`: https://gitlab.labs.nic.cz/knot/resolver/blob/master/README.md
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/
.. _here: https://git.samba.org/?p=socket_wrapper.git;a=blob;f=doc/socket_wrapper.1.txt;hb=HEAD
.. _`scenario guide` : https://gitlab.labs.nic.cz/knot/deckard/blob/master/SCENARIO_GUIDE.rst

