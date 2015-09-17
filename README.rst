DNS software test harness
=========================

The tests depend on cwrap's `socket_wrapper`_, libfaketime_ and Python.
The libfaketime is included in ``contrib/libfaketime`` as it depends on rather latest version of it,
it is automatically synchronised with ``make``.

Execute the tests by:

.. code-block:: bash

	$ make DAEMON=/usr/local/bin/kresd

.. todo:: Writing tests.

.. _cmocka: https://cmocka.org/
.. _`socket_wrapper`: https://cwrap.org/socket_wrapper.html
.. _libfaketime: https://cwrap.org/socket_wrapper.html
