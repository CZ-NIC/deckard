DNS test harness (Deckard)
==========================

Deckard is a DNS software testing tool that creates a controlled network environment for reproducible tests.

In essence, it works like this:

- Deckard runs given binaries as subprocesses in an isolated network environment.
- When binaries are up, Deckard sends scripted queries and checks replies.
- When a binary attempts to contact another server, Deckard intercepts the communication and replies with scripted answer.
- Deckard can simulate network issues, DNS environment changes, and fake time (for DNSSEC validation tests).

No changes to real network setup are required because all network communications are made in a network namespace.

Test cases are described by `scenarios <doc/scenario_guide.rst>`_ that contain:

- A declarative description of the environment (e.g. what queries can the binary under test make and what Deckard should answer)
- A sequence of queries (and expected answers), and other events (e.g. time jumps forward)


Requirements
------------

Deckard requires following software to be installed:

- Python >= 3.6
- Linux kernel >= 3.8
- augeas_ - library for editing configuration files
- dnspython_ - DNS library for Python
- Jinja2_ - template engine for generating config files
- PyYAML_ - YAML parser for Python
- python-augeas_ - Python bindings for augeas API
- pytest_ - testing framework for Python, used for running the test cases
- pytest-xdist_ - module for pytest for distributed testing
- pytest-forked_ - module for pytest for testing in forked subprocesses
- pyroute2_ - Python netlink library (managing IP addresses, routes,…)
- dumpcap_ - command line tool for network capture (part of Wireshark)
- faketime_ - used for faking the time in tests of DNSSEC

Compatibility
-------------

Deckard uses user and network namespaces to simulate the network environment
so only Linux (with kernel version 3.8 or newer) is supported. It however is possible
to run Deckard on other platforms in Docker. Just note that your container has to run as
`--priviledged` for the namespaces to run properly.

Usage
-----

- `User guide <doc/user_guide.rst>`_ describes how to run tests on a binary.
- `Scenario guide <doc/scenario_guide.rst>`_ describes how to write a new test.
- `Devel guide <doc/devel_guide.rst>`_ contains some tips for Deckard developers.


License
-------

See `LICENSE <LICENSE>`_ file.


Acknowledgments
---------------

The test scenario design and a lot of tests were written by `NLnet Labs`_ for ``testbound`` suite used by `Unbound`_ (BSD licensed). We are grateful that ``testbound`` authors are `willing to discuss <https://unbound.nlnetlabs.nl/pipermail/unbound-users/2017-March/004699.html>`_ further Deckard development.

The original test case format is described in the `header file replay.h <http://unbound.net/documentation/doxygen/replay_8h.html#a6f204646f02cc4debbaf8a9b3fdb59a7>`_ distributed with `Unbound`_.


Contacting us
-------------

Please report problems to our GitLab: https://gitlab.nic.cz/knot/deckard/issues

If you have any comments feel free to send e-mail to knot-resolver@labs.nic.cz! Do not get confused by the name, we are happy if you want to use Deckard with any software.

Happy testing.


.. _`augeas`: http://augeas.net/
.. _`CSR`: http://apple.stackexchange.com/questions/193368/what-is-the-rootless-feature-in-el-capitan-really
.. _`Jinja2`: http://jinja.pocoo.org/
.. _`Knot Resolver`: https://gitlab.nic.cz/knot/resolver/blob/master/README.md
.. _`NLnet Labs`: https://www.nlnetlabs.nl/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/
.. _`PyYAML`: http://pyyaml.org/
.. _`Unbound`: https://www.unbound.net/
.. _`dnspython`: http://www.dnspython.org/
.. _`libfaketime`: https://github.com/wolfcw/libfaketime
.. _`python-augeas`: https://pypi.org/project/python-augeas/
.. _`pytest`: https://pytest.org/
.. _`pytest-xdist`: https://pypi.python.org/pypi/pytest-xdist
.. _`pytest-forked`: https://pypi.python.org/pypi/pytest-forked
.. _`pyroute2`: https://pyroute2.org/
.. _`dumpcap`: https://www.wireshark.org/docs/man-pages/dumpcap.html
