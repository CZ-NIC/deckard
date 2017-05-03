Notes for Deckard developers
============================

socket wrapper library (cwrap)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Detailed instructions on using cwrap you can be found here_

cwrap environment is managed by Deckard. Default values are sufficient, do not touch the environment unless you are trying to debug something. Variables available for direct use are:

- ``SOCKET_WRAPPER_DIR`` is a generic working directory. It defaults
  to a new temporary directory with randomly generated name,
  prefixed by ``tmpdeckard``. When a test fails, the work directory can contain useful
  information for post-mortem analysis. You can explicitly set ``SOCKET_WRAPPER_DIR``
  to a custom path for more convenient analysis.
- ``SOCKET_WRAPPER_DEBUGLEVEL`` is not set by default.

Deckard automatically sets ``SOCKET_WRAPPER_PCAP_FILE`` to create separate PCAP files in working directory for Deckard itself and each daemon. Feel free to inspect them.

.. _here: https://git.samba.org/?p=socket_wrapper.git;a=blob;f=doc/socket_wrapper.1.txt;hb=HEAD


libfaketime
^^^^^^^^^^^
Run-time changes to ``FAKETIME_`` environment variables might not be picked up by running process if ``FAKETIME_NO_CACHE=1`` variable is not set before the process starts.
