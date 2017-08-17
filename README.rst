DNS test harness (Deckard)
==========================

Deckard is a DNS software testing tool that creates a controlled network environment for reproducible tests.

In essence, it works like this:

- Deckard runs given binaries as subprocesses in an isolated network environment.
- When binaries are up, Deckard sends scripted queries and checks replies.
- When a binary attempts to contact another server, Deckard intercepts the communication and replies with scripted answer.
- Deckard can simulate network issues, DNS environment changes, and fake time (for DNSSEC validation tests).

No changes to real network setup are required because all network communications are redirected over UNIX sockets (and recorded to PCAP).

Test cases are described by `scenarios <doc/scenario_guide.rst>`_ that contain:

- A declarative description of the environment (e.g. what queries can the binary under test make and what Deckard should answer)
- A sequence of queries (and expected answers), and other events (e.g. time jumps forward)


Requirements
------------

Deckard requires following software to be installed:

- Python >= 3.3
- dnspython_ - DNS library for Python
- Jinja2_ - template engine for generating config files
- PyYAML_ - YAML parser for Python
- custom C libraries (installed automatically, see below)

For convenient use it is strongly recommended to have a C compiler, Git, and ``make`` available.
First execution of ``make`` will automatically download and compile following libraries:

- libfaketime_ - embedded because Deckard requires a rather recent version
- `modified socket_wrapper`_ - custom modification of `original socket_wrapper`_ library (part of the cwrap_ tool set for creating an isolated networks)


Compatibility
-------------

Works well on Linux, Mac OS X [#]_ and probably all BSDs. Tested with `Knot DNS Resolver`_, `Unbound`_, and `PowerDNS Recursor`_. It should work with other software as well as long as all functions used by the binary under test are supported by our `modified socket_wrapper`_.

.. [#] Python from Homebrew must be used, as the built-in Python is protected by the CSR_ from OS X 10.11 and prevents library injection.


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

Please report problems to our GitLab: https://gitlab.labs.nic.cz/knot/deckard/issues

If you have any comments feel free to send e-mail to knot-dns@labs.nic.cz! Do not get confused by the name, we are happy if you want to use Deckard with any software.

Happy testing.


.. _`CSR`: http://apple.stackexchange.com/questions/193368/what-is-the-rootless-feature-in-el-capitan-really
.. _`Jinja2`: http://jinja.pocoo.org/
.. _`Knot DNS Resolver`: https://gitlab.labs.nic.cz/knot/resolver/blob/master/README.md
.. _`NLnet Labs`: https://www.nlnetlabs.nl/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/
.. _`PyYAML`: http://pyyaml.org/
.. _`Unbound`: https://www.unbound.net/
.. _`cwrap`: https://cwrap.org/
.. _`dnspython`: http://www.dnspython.org/
.. _`libfaketime`: https://github.com/wolfcw/libfaketime
.. _`modified socket_wrapper`: https://gitlab.labs.nic.cz/labs/socket_wrapper
.. _`original socket_wrapper`: https://cwrap.org/socket_wrapper.html
