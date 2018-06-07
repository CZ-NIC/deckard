Deckard scenario guide
======================
.. contents::

On the highest level, Deckard scenario consists of three parts (in this order):

- scenario-specific configuration in the header,
- declarative description of the simulated network environment,
- sequence of test steps.

The scenario is stored as ASCII encoded text file with following structure:

.. code-block::

   ; configuration part starts on beginning of the file
   ; comments start with semicolon
   CONFIG_END

   SCENARIO_BEGIN       ; SCENARIO block combines declarative description and sequence of steps


   ; declarative description of network environment starts here
   RANGE_BEGIN a b
   ENTRY_BEGIN
       ; entries inside RANGE block describe DNS messages
       ; used as answers from simulated network
   ENTRY_END
   RANGE_END


   ; sequence of test steps begins here
   STEP x QUERY         ; this is step number x
   ENTRY_BEGIN
       ; ENTRY inside STEP may describe DNS message sent as query
   ENTRY_END

   STEP y CHECK_ANSWER  ; arbitrary number of steps is allowed
   ENTRY_BEGIN
       ; also, ENTRY inside STEP may describe DNS message with expected answer
   ENTRY_END
   SCENARIO_END

The scenario is processed as follows:

- Deckard parses configuration block and generates configuration files for binaries under test
- binaries are executed in an isolated network environment
- Deckard walks through all ``STEP`` blocks and sends queries to the binary under test, and checks answers it receives
- when a binary attempts to contact another server, Deckard intercepts the communication and replies with scripted answer as defined in ``RANGE`` blocks

To better understand this structure, we will walk-through from sequential steps through declarative description up to scenario-specific configuration.

Scenario
--------
Scenario part starts with ``SCENARIO_BEGIN`` and ends with ``SCENARIO_END`` statements, which are present after ``CONFIG_END`` keyword. ``SCENARIO_BEGIN`` keyword must be followed by scenario description:

.. code-block::

    SCENARIO_BEGIN Test basic query minimization www.example.com.
    ...
    SCENARIO_END



Test steps (``STEP``)
---------------------
One ``STEP`` describes one action during scenario execution. It might be action like send next query to binary under test, send reply to binary under test, change faked system time, or check the last answer. Sequence of two steps might look like this:

.. code-block::

   STEP 1 QUERY          ; send query specified in the following ENTRY to the binary
   ENTRY_BEGIN           ; ENTRY defines content of DNS message
   REPLY RD
   SECTION QUESTION
   www.example.com. IN A
   ENTRY_END

   STEP 10 CHECK_ANSWER  ; check that answer to the previous query matches following ENTRY
   ENTRY_BEGIN
   MATCH all             ; MATCH specifies what fields in answer have to match the ENTRY
   REPLY QR RD RA NOERROR
   SECTION QUESTION
   www.example.com. IN A
   SECTION ANSWER
   www.example.com. IN CNAME       www.next.com.
   www.next.com. IN A 10.20.30.40
   SECTION AUTHORITY
   SECTION ADDITIONAL
   ENTRY_END


Most important parts of a step are:

- id - number specifying order in which steps are executed, e.g. ``1`` or ``10``
- type - action to execute, e.g. ``QUERY`` or ``CHECK_ANSWER``
- entry - DNS message content, while meaning of the message depends on the step *type*

One ``STEP`` block starts with ``STEP`` keyword and continues until one of {``STEP``,
``RANGE``, ``END_SCENARIO``} keywords is found.

Format
^^^^^^

.. code-block::

   STEP id type [additional data]

- id - step identifier, a positive integer value; all steps must have
  different id's. This value used within RANGE block, see above.
- type - step type; can be ``QUERY`` | ``REPLY`` | ``CHECK_ANSWER`` | ``TIME_PASSES ELAPSE`` *seconds*

  - QUERY - send query defined by associated ``ENTRY`` to binary under test
  - CHECK_ANSWER - check if last received answer matches associated ``ENTRY``
  - TIME_PASSES ELAPSE - move faked system time for binary under test by number of *seconds* to future
  - REPLY - *use of this type is discouraged*; it defines one-shot reply to query from binary under test

.. warning::
    - ``REPLY`` type is useful only if you know exact order of queries sent *by the binary under test*
    - steps of this type are used only when no matching ``RANGE`` datablock exists
    - priority of ``REPLY`` type is going to change in future


.. _entry:

DNS messages (normal ``ENTRY``)
-------------------------------
One ``ENTRY`` describes one DNS message plus additional metadata, depending on intended use of the entry. There are three possible uses of entry which require little bit different entry format. An entry might define:

#. *query message* to be sent in ``STEP QUERY``
#. *expected message* to be compared with a message received from binary in ``STEP CHECK_ANSWER``
#. *answer template message* to be used for simulating answers from network in ``RANGE`` block

Particular use of data in an ``ENTRY`` depends on context and is different
for ``STEP`` types and ``RANGE`` blocks, see details below.

In any case, entry starts with ``ENTRY_BEGIN`` and ends with ``ENTRY_END`` keywords and share ``REPLY`` and ``SECTION`` definitions.
Some fields in DNS messages have default values which can be overriden by explicit specification.

Format of query messages (for ``STEP QUERY``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
``STEP QUERY`` requires a DNS message which will be sent by Deckard to the binary under test. Structure of the entry is:

.. code-block::

    STEP <n> QUERY
    ENTRY_BEGIN
    REPLY <OPCODE flags>    ; REPLY is a bad keyword name, OPCODE and flags will be sent out!
    SECTION QUESTION        ; it is possible to replace QUESTION section or omit it
    <name> <class> <type>   ; to simulate weird queries
    ENTRY_END

The message will be assigned a random message ID, converted into DNS wire format, and sent to the binary under test.

.. warning:: The keyword ``REPLY`` in fact defines value of flags in the outgoing message. The confusing name is here for compatibility with the original ``testbound``.


Format of expected messages (for ``STEP CHECK_ANSWER``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
``STEP CHECK_ANSWER`` requires a DNS message which will be compared with a reply received from the binary under test. Structure of the entry describing the expected message is:

.. code-block::

    ENTRY_BEGIN
    MATCH <match element list>  ; MATCH elements define what message fields will be compared
    REPLY <OPCODE RCODE flags>  ; REPLY field here defines expected OPCODE, RCODE as well as flags!
    SECTION QUESTION
    <name> <class> <type>       ; to simulate weird queries
    SECTION <type2>
    <RR sets>
    ENTRY_END

Deckard will compare messages according to *<match element list>*. Any mismatch between *received* message and the *expected* message (specified by the entry) will result in test failure. (See chapter `entry matching`_.)


Format of answer templates (for ``RANGE``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Entries in ``RANGE`` blocks are used to answer queries *from binaries under test*. E.g. if a DNS resolver under test sends query ``. IN NS`` to a simulated server, Deckard will use matching entry associated with the simulated server for reply. Entry used for answer is selected using the same `entry matching`_ logic as with ``STEP CHECK_ANSWER``. The difference is that entry is automatically modified before sending out the answer. These modifications are specified by ``ADJUST`` and ``REPLY`` keywords. See chapters `entry adjusting`_ and `entry flags`_.

.. code-block::

    ENTRY_BEGIN
    MATCH <match element list>    ; all MATCH elements must match before using this answer template
    ADJUST <adjust element list>  ; ADJUST fields will be modified before answering
    REPLY <OPCODE RCODE flags>    ; OPCODE, RCODE, and flags to be set in the outgoing answer
    SECTION <type1>
    <RR sets>
    SECTION <type2>
    <RR sets>
    ENTRY_END


.. _`entry matching`:

Entry matching
^^^^^^^^^^^^^^
Entries present in Deckard scenario define values *expected* in DNS messages. The *expected* values are compared with values in messages *received* from the network. Entry matches only if all specified elements match.

.. code-block::

   MATCH <match element list>

*<match element list>* is a space-separated list of elements in *expected* and *received* messages to be compared. Supported elements are:

============ =========================================================================================
element      DNS message fields and additional rules
============ =========================================================================================
opcode       ``OPCODE`` as `defined in IANA registry <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5>`_

             - *expected* message ``OPCODE`` is defined by ``REPLY`` keyword

qtype        RR type in question section [qmatch]_
qname        name in question section (case insensitive) [qmatch]_
qcase        name in question section (case sensitive) [qmatch]_
subdomain    name in question section of the *received* message is a subdomain of the name in *expected* question section
             (case insensitive, exact match accepted) [qmatch]_
flags        all `defined flags <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12>`_
             in message header: ``QR AA TC RD RA AD CD``

             - it does not match on ``DO`` flag which resides in EDNS header flags
             - *expected* message flags are defined by ``REPLY`` keyword

rcode        extended response code (``RCODE`` value
             `combined from message header and EDNS header <https://tools.ietf.org/html/rfc6891#section-6.1.3>`_)

             - *expected* message ``RCODE`` is defined by ``REPLY`` keyword

question     whole QUESTION section [sectmatch]_
answer       whole ANSWER section [sectmatch]_
authority    whole AUTHORITY section [sectmatch]_
additional   whole ADDITIONAL section [sectmatch]_
edns         EDNS `version <https://tools.ietf.org/html/rfc6891#section-6.1.3>`_ and
             EDNS `payload <https://tools.ietf.org/html/rfc6891#section-6.1.2>`_ size
nsid         `NSID <https://tools.ietf.org/html/rfc5001>`_ presence and value
all          equivalent to ``flags`` + ``rcode`` + all sections explicitly defined in the ``ENTRY``

             - sections present in the *received* message but not explicitly defined in the *expected* entry are ignored
============ =========================================================================================

.. [qmatch] *Expected* values are defined by QUESTION section in the entry. If the *expected* QUESTION section is empty, the conditions is ignored. Only values from the first (qname, qclass, qtype) tuple are checked. Question matching is case insensitive (except for ``qcase``).

.. [sectmatch] Number of records must match. Owner names are case-insensitive and TTL is ignored. RR data are compared according to type-specific rules. Each RR present in the *expected* message must be present in the *received* message and vice versa.


.. _`entry adjusting`:

Entry adjusting
^^^^^^^^^^^^^^^
.. code-block::

   ADJUST <adjust element list>

An entry used as a template to prepare an answer to an incoming query might be preprocessed.
Adjust element list defines what fields will be modified:

========== ===========================================================================================
element    modification to the DNS message
========== ===========================================================================================
copy_id    query id + query domain name will be copied from incoming message [copy_id_bug]_
copy_query whole question section will be copied from incoming message
========== ===========================================================================================

.. [copy_id_bug] https://gitlab.labs.nic.cz/knot/deckard/issues/9


.. _`entry flags`:

Entry flags
^^^^^^^^^^^
.. code-block::

  REPLY <RCODE flags>

*<RCODE flags>* is space-separated RCODE and list of flags in the entry. Usage of these flags depend on entry context.

Supported values:

  - NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, YXDOMAIN, YXRRSET, NXRRSET, NOTAUTH, NOTZONE, BADVERS - standard rcodes
  - QR, AA, TC, RD, RA, AD, CD - i.e. standard dns flags
  - DO - enable 'DNSSEC desired' flag

.. warning:: The keyword ``REPLY`` has different meaning depending on the ``ENTRY`` context.


Entry RR sections
^^^^^^^^^^^^^^^^^
An entry might specify content of DNS message sections QUESTION, ANSWER, AUTHORITY, and ADDITIONAL. Syntax is of resource records is the same as in zone file. Format:

.. code-block::

   SECTION QUESTION
   <owner name> [class] <RR type>                  ; QUESTION is special
   SECTION <ANSWER/AUTHORITY/ADDITIONAL>
   <owner name> [TTL] [class] <RR type> <RR data>  ; same as in zone file
   ...
   <owner name> [TTL] [class] <RR type> <RR data>

Example:

.. code-block::

   SECTION QUESTION
   www.example.com.	IN A
   SECTION ANSWER
   www.example.com.	IN A	10.20.30.40
   SECTION AUTHORITY
   example.com.	IN NS	ns.example.com.
   SECTION ADDITIONAL
   ns.example.com.	IN A	1.2.3.4


Default values for DNS messages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
========== ===========================================================================================
feature    default value
========== ===========================================================================================
ADJUST     copy_id
EDNS       version 0 with buffer size 4096 B
MATCH      opcode, qtype, qname
REPLY      QUERY, NOERROR
========== ===========================================================================================


Entry with RAW data
^^^^^^^^^^^^^^^^^^^
An entry might have special section named ``RAW``. This section is used only for sending raw,
potentially invalid DNS messages. The section contains a single-line data interpreted as hexadecimal string.
Data decoded from this string will be sent to binary under test without any changes.

Deckard does not expect any answer to RAW queries, so ``STEP CHECK_ANSWER`` is not needed.
Main intent of this behavior is to check if binary under test is
able to process valid queries after getting series badly formed packets.

It is also possible to use ``RAW`` in conjuction with ``SECTION`` for the
purpose of responding with raw data to a query that matches the ``SECTION``.
Raw data is sent as is and isn't manipulated in any way (e.g. by ``ADJUST``).

One ``ENTRY`` can contain only one ``RAW`` section.

Example

.. code-block::

   ENTRY_BEGIN
   RAW
   b5c9ca3d50104320f4120000000000000000
   ENTRY_END



Mock answers (``RANGE``)
------------------------
When Deckard receives a query *from binary under test*, it searches for mock answers.
A set of mock answers for particular set of IP addresses and ID range is described using ``RANGE``
block starting with ``RANGE_BEGIN`` keyword. The ``RANGE`` contains mock DNS messages represented
as ENTRY_ blocks which specify `entry matching`_ conditions along with `entry adjusting`_ actions and `entry flags`_ specification.

Format:

.. code-block::

   ; comment before the range, e.g. K.ROOT-SERVERS.NET.
   RANGE_BEGIN 0 100              ; this RANGE is valid for STEP IDs <0, 100>
           ADDRESS 193.0.14.129   ; IP address simulated by this range
           ;ADDRESS 192.0.2.222   ; multiple IP addresses are allowed

   ENTRY_BEGIN                    ; first ENTRY in this range
   MATCH opcode qtype qname       ; use this entry only if all these match the query
   ADJUST copy_id                 ; adjust message ID before senting the answer
   REPLY QR NOERROR               ; answer with RCODE NOERROR and QR flag set
   SECTION QUESTION
   . IN NS                        ; MATCH qname qtype are compared with this value
   SECTION ANSWER                 ; all this will be copied verbatim to the answer
   . IN NS K.ROOT-SERVERS.NET.
   SECTION ADDITIONAL
   K.ROOT-SERVERS.NET.     IN      A       193.0.14.129
   ENTRY_END

   ENTRY_BEGIN                    ; second ENTRY in this range
   ...
   ENTRY_END

   RANGE_END

When Deckard receives a query *from binary under test*, it searches for an eligible range. When an eligible range is found, it searches inside the range to find a mock answer. In detail, it works like this:

#. Deckard searches for an eligible ``RANGE`` block. Following two conditions must be fulfilled:

   - current ``STEP ID`` is inside ID range specified by ``RANGE_BEGIN`` keyword.
   - target IP address of the query is in set of IP addresses specified using ``ADDRESS`` keywords

#. If an eligible range is found, Deckard examines all entries in the range and evaluate all ``MATCH`` conditions associated with entries.
#. An entry where all MATCH conditions are fulfilled is used as template for the mock answer. (See `entry matching`_.)
#. Mock answer is modified according to ``ADJUST`` and ``REPLY`` keywords. (See `entry adjusting`_ actions and `entry flags`_ specification.)
#. The modified answer message is sent to the binary under test.

Valid scenario must specify answers for all queries generated by the binary under test. The test will fail if no answer is found in the eligible range or if no eligible range is defined.

.. note:: Behavior of the binary under test, including queries it generates, depends on its configuration. For example enabling or disabling query name minimization will change minimal set of queries which a test scenario has to describe using ``RANGE`` blocks.

.. tip:: It is recommended to construct scenarios that support multiple configurations and possibly software implementations. This leads to higher number of entries in ``RANGE`` blocks but provides robustness against changes in particular implementation. E.g. a scenario for DNS resolver testing can be developed using multiple DNS resolver implementations and combine entries for all of them inside single scenario. With this approach a small change in a resolver implementation will likely not require further changes to the scenario.


Configuration (``CONFIG_END``)
------------------------------
Configuration block affects behavior of the binary under test. Deckard transforms configuration block into configuration for the binary under test.

Format is list of "key: value" pairs, one pair per line. There is no explicit start keyword, configuration block starts immediately at scenario file begin and ends with keyword ``CONFIG_END``.

.. code-block::

   ; config options
           query-minimization: on
           stub-addr: 193.0.14.129 	; K.ROOT-SERVERS.NET.
           trust-anchor: ". 3600 IN DS 10000 13 4 ABCDEF0123456789"
           val-override-date: "1442323400"
   CONFIG_END

========================== ======= =====================================================================
config option              default meaning
========================== ======= =====================================================================
do-not-query-localhost     on      on = queries cannot be sent to 127.0.0.1/8 or ::1/128 addresses
domain-insecure            (none)  domain name specifying DNS sub-tree with explicitly disabled DNSSEC validation
force-ipv6                 off     use a IPv6 address as ``stub-addr``
harden-glue                on      additional checks on glue addresses
query-minimization         on      RFC 7816 query algorithm enabled; default inherited from QMIN environment variable
stub-addr                  (none)  IP address for resolver priming queries (RFC 8109)
trust-anchor               (none)  owner name with its DS records (this option can be repeated multiple times)
val-override-date          (none)  system time reported to binary under the test; format ``YYYYMMDDHHMMSS``, so ``20120420235959`` means ``Fri Apr 20 23:59:59 2012``
val-override-timestamp     (none)  system time reported to binary under the test: format POSIX timestamp
========================== ======= =====================================================================

Examples
--------
See `scenatio example <scenario_example.rst>`_. The example there is a bit terse but still valid.
