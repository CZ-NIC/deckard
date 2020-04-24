Notes for Deckard developers
============================

libfaketime
^^^^^^^^^^^
Run-time changes to ``FAKETIME_`` environment variables might not be picked up by running process if ``FAKETIME_NO_CACHE=1`` variable is not set before the process starts.
