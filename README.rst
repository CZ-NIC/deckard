DNS test harness (Deckard)
==========================

Deckard is a DNS software testing tool that creates a controlled environment for reproducible tests.
In essence - it runs given binary as a subprocess, sends it scripted queries, and intercepts queries
from the tested binary. It can simulate network issues, DNS environment changes, and fake time.

All network communications are redirected `over UNIX sockets <socket_wrapper>`_.
Test cases are written in `scenarios <SCENARIO_GUIDE.rst>`_, that contain:

- A declarative description of the environment (e.g. what queries can the subject make)
- A sequence of queries (and expected answers), and other events (e.g. what should the subject answer)

Requirements
------------

Deckard requires next software to be installed:

- Python >= 2.7
- dnspython_ - DNS library for Python.
- Jinja2_ - template engine for generating config files.
- `socket_wrapper`_ - a modification of `initial socket_wrapper`_ library (part of the cwrap_ tool set for creating an isolated networks).

It also depends on libfaketime_, but it is embedded as it requires a rather recent version (automatically synchronised with ``make``).

Compatibility
-------------

Works well on Linux, Mac OS X [#]_ and probably all BSDs. Tested with `Knot DNS Resolver`_ and `PowerDNS Recursor`_.

.. [#] Python from Homebrew must be used, as the built-in Python is protected by the CSR_ from OS X 10.11 and prevents library injection.

How to use it
-------------
    
Create a config file template
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the tested server accepts a config file(s), you have to create a template for it.
Deckard uses the Jinja2_ templating engine (like Ansible or Salt) with several variables that you can use.
It's okay if you don't use them, but expect some tests to fail (i.e. if you don't set the ``TRUST_ANCHOR``,
then the DNSSEC tests won't work properly).

- ``ROOT_ADDR``    - root server hint. Port is not set and assumed to be equal to 53.
- ``SELF_ADDR``    - assigned address for the tested binary. Port is not set and assumed to be equal to 53.
- ``NO_MINIMIZE``  - ``'true'`` or ``'false'``, disables or enables query minimization respectively. (Default: disabled)
- ``WORKING_DIR``  - working directory, equivalent to the value of a ``SOCKET_WRAPPER_DIR``
  environment variable.
- ``INSTALL_DIR``  - Deckard home directory
- ``TRUST_ANCHOR`` - a trust anchor in form of a DS record, see `scenario guide <https://gitlab.labs.nic.cz/knot/deckard/blob/master/SCENARIO_GUIDE.rst>`_.

Setting up the test
^^^^^^^^^^^^^^^^^^^

You can alter test process using the Makefile variables:

- ``TESTS``        - path to scenario files; default: ``sets/resolver``
- ``DAEMON``       - path to binary have to be tested; default: ``kresd``
- ``TEMPLATE``     - colon-separated list of jinja2 template files to generate configuration files; default: ``kresd.j2``
- ``CONFIG``       - colon-separated list of names of configuration files to be generated; resulting files will be generated  respectively to the ``TEMPLATE`` file list, i.e. first file in list is the result of processing of the first file from ``TEMPLATE`` list, etc.; default: ``config``

- ``ADDITIONAL``   - additional parameters for binary, intended to test; not set by default

Run it
^^^^^^

Execute the tests by running **make**:

.. code-block:: bash

    make TESTS=sets/resolver DAEMON=/usr/local/bin/kresd TEMPLATE=kresd.j2 CONFIG=config

These are the default values for Knot DNS Resolver.

Examples
--------

1. Configuration file example for Knot DNS Resolver:

.. code-block:: lua

    net = { '{{SELF_ADDR}}' }
    modules = {'stats', 'policy', 'hints'}
    hints.root({['k.root-servers.net'] = '{{ROOT_ADDR}}'})
    option('NO_MINIMIZE', {{NO_MINIMIZE}})
    option('ALLOW_LOCAL', true)
    trust_anchors.add('{{TRUST_ANCHOR}}')


2. Configuration file example for PowerDNS Recursor [#]_:

::

    # config-dir    Location of configuration directory (recursor.conf)
    config-dir={{WORKING_DIR}}
    # local-address IP addresses to listen on, separated by spaces or commas. Also accepts ports.
    local-address={{SELF_ADDR}}
    # socket-dir    Where the controlsocket will live
    socket-dir={{WORKING_DIR}}
    # hint-file	If set, load root hints from this file
    hint-file={{INSTALL_DIR}}/template/hints.pdns

.. [#] Only changed directives in the default config are shown.

3. Test script for PowerDNS Recursor:

.. code-block:: bash

    #!/bin/bash
    TESTS=sets/resolver 
    DAEMON=pdns_recursor
    TEMPLATE=recursor.j2 
    CONFIG=recursor.conf
    ADDITIONAL=--config-dir=./
    export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL
    make

For developers
--------------

Writing your own scenario
^^^^^^^^^^^^^^^^^^^^^^^^^

See `scenario guide <https://gitlab.labs.nic.cz/knot/deckard/blob/master/SCENARIO_GUIDE.rst>`_

Setting up socket wrapper library (cwrap)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Detailed instructions on using cwrap you can read here_

Generally, explicit environment setup for cwrap is not required. 
When cwrap environment is absent, default values will be used :

- ``SOCKET_WRAPPER_DEFAULT_IFACE`` = 2
- ``SOCKET_WRAPPER_DIR`` will be created in default temporary directory with 
  randomly generated name, prefixed by ``/tmp``
- ``SOCKET_WRAPPER_DEBUGLEVEL`` will not be set

``SOCKET_WRAPPER_DIR`` can also be used as a work directory for binary under test. When a test 
fails, the work directory can contain useful information for post-mortem analysis. You can explicitly
set ``SOCKET_WRAPPER_DIR`` to a custom path for more convenient analysis.

Acknowledgments
---------------

The test scenario design and a lot of tests were written for `NLnetLabs Unbound <http://unbound.net/index.html>`_ (BSD licensed).
The original test case format is described in the `Doxygen documentation <http://unbound.net/documentation/doxygen/replay_8h.html#a6f204646f02cc4debbaf8a9b3fdb59a7>`_.

.. _cwrap: https://cwrap.org/
.. _`dnspython`: http://www.dnspython.org/
.. _Jinja2: http://jinja.pocoo.org/
.. _`socket_wrapper`: https://gitlab.labs.nic.cz/labs/socket_wrapper
.. _`initial socket_wrapper`: https://cwrap.org/socket_wrapper.html
.. _Libfaketime: https://github.com/wolfcw/libfaketime
.. _`Knot DNS Resolver`: https://gitlab.labs.nic.cz/knot/resolver/blob/master/README.md
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/
.. _here: https://git.samba.org/?p=socket_wrapper.git;a=blob;f=doc/socket_wrapper.1.txt;hb=HEAD
.. _CSR: http://apple.stackexchange.com/questions/193368/what-is-the-rootless-feature-in-el-capitan-really
