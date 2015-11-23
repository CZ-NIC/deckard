Scenario example
=================
iter_ns_badaa.rpl
::

  ; config options
  	stub-addr: 193.0.14.129 	# K.ROOT-SERVERS.NET.
  CONFIG_END

  SCENARIO_BEGIN Test iterator with NS falsely declaring referral answer as authoritative.

  ; K.ROOT-SERVERS.NET.
  RANGE_BEGIN 0 100
	ADDRESS 193.0.14.129 
  ENTRY_BEGIN
  MATCH opcode qtype qname
  ADJUST copy_id
  REPLY QR NOERROR
  SECTION QUESTION
  . IN NS
  SECTION ANSWER
  . IN NS	K.ROOT-SERVERS.NET.
  SECTION ADDITIONAL
  K.ROOT-SERVERS.NET.	IN	A	193.0.14.129
  ENTRY_END

  ENTRY_BEGIN
  MATCH opcode subdomain
  ADJUST copy_id copy_query
  ; False declaration here
  REPLY QR AA NOERROR
  SECTION QUESTION
  MORECOWBELL. IN A
  SECTION AUTHORITY
  MORECOWBELL.	IN NS	a.gtld-servers.net.
  SECTION ADDITIONAL
  a.gtld-servers.net. IN A 192.5.6.30
  ENTRY_END

  ENTRY_BEGIN
  MATCH opcode qtype qname
  ADJUST copy_id copy_query
  REPLY QR NOERROR
  SECTION QUESTION
  a.gtld-servers.net.	IN	A
  SECTION ANSWER
  a.gtld-servers.net.	IN 	A	192.5.6.30
  ENTRY_END

  ENTRY_BEGIN
  MATCH opcode qtype qname
  ADJUST copy_id copy_query
  REPLY QR NOERROR
  SECTION QUESTION
  a.gtld-servers.net.	IN	AAAA
  SECTION AUTHORITY
  . SOA bla bla 1 2 3 4 5
 ENTRY_END

  RANGE_END

  ; a.gtld-servers.net.
  RANGE_BEGIN 0 100
	ADDRESS 192.5.6.30

  ENTRY_BEGIN
  MATCH opcode qtype qname
  ADJUST copy_id copy_query
  REPLY QR AA NOERROR
  SECTION QUESTION
  CATALYST.MORECOWBELL. IN A
  SECTION ANSWER
  CATALYST.MORECOWBELL. IN A	10.20.30.40
  SECTION AUTHORITY
  CATALYST.MORECOWBELL.	IN NS	a.gtld-servers.net.
  ENTRY_END

  RANGE_END

  STEP 1 QUERY
  ENTRY_BEGIN
  REPLY RD
  SECTION QUESTION
  catalyst.morecowbell. IN A
  ENTRY_END

  ; recursion happens here.
  STEP 10 CHECK_ANSWER
  ENTRY_BEGIN
  MATCH all
  REPLY QR RD RA NOERROR
  SECTION QUESTION
  catalyst.morecowbell. IN A
  SECTION ANSWER
  catalyst.morecowbell. IN A 10.20.30.40
  ENTRY_END

  SCENARIO_END

Execution flow :

First, STEP 1 QUERY will be performed. 

Python sends query to Resolver
::

    id 31296
    opcode QUERY
    rcode NOERROR
    flags RD
    edns 1
    eflags 
    payload 1280
    ;QUESTION
    catalyst.morecowbell. IN A
    ;ANSWER
    ;AUTHORITY
    ;ADDITIONAL

At this scenario stub-addr is set to 193.0.14.129, thus Resolver have been configured to use address 
193.0.14.129 as a root server. So it sends query to Python fake server which listen at address 193.0.14.129

::

    > [plan] plan 'catalyst.morecowbell.' type 'A'
    [resl]   => using root hints
    [resl]   => querying: '193.0.14.129' score: 10 zone cut: '.' m12n: 'CaTALYSt.MoReCoWBEll.' type: 'A'


::

    id 7367
    opcode QUERY
    rcode NOERROR
    flags 
    edns 0
    payload 1452
    ;QUESTION
    CaTALYSt.MoReCoWBEll. IN A
    ;ANSWER
    ;AUTHORITY
    ;ADDITIONAL

Python fake server starts range analyzing to make answer.
Let's look at first range
::

    RANGE_BEGIN 0 100
	    ADDRESS 193.0.14.129 

STEP ID is equal 1, so it matches the condition n1 <= step id <= n2
Next, ADDRESS field is equal to 193.0.14.129. Since query was directed 
specifically to 193.0.14.129, this range will be used.

Next, Python walks through list of entries to choose eligible entry.
First entry at this range requires comparison of "opcode qtype qname" field list.
Since opcode is QUERY, first comparison is true.
Next, qtype field at question section is equal NS.
But qtype field at question section of incoming query is A.
So this comparison failed and this entry will be rejected.

Next entry requires comparison of opcode and subdomain fields.
As we seen, opcode matches.
Let's look at domain names.
ENTRY datablock:
::

    SECTION QUESTION
    MORECOWBELL. IN A

Incoming query :
::

    ;QUESTION
    CaTALYSt.MoReCoWBEll. IN A

So, subdomain matches and second entry of first range used as answer pattern.
Python fake server sends answer to Resolver :
::

    id 7367
    opcode QUERY
    rcode NOERROR
    flags QR AA
    edns 0
    payload 1280
    ;QUESTION
    CaTALYSt.MoReCoWBEll. IN A
    ;ANSWER
    ;AUTHORITY
    MORECOWBELL. 3600 IN NS a.gtld-servers.net.
    ;ADDITIONAL
    a.gtld-servers.net. 3600 IN A 192.5.6.30

Note that additional section contains IP address. Because new address is found, 
Python fake server immediately starts listening on this address.
Resolver sends next query to 192.5.6.30:

::

    [iter]   <= referral response, follow
    [ pc ]   => answer cached for TTL=900
    [resl]   => querying: '192.5.6.30' score: 10 zone cut: 'morecowbell.' m12n: 'catalyst.mOREcoWBEll.' type: 'A'


::

    id 58167
    opcode QUERY
    rcode NOERROR
    flags 
    edns 0
    payload 1452
    ;QUESTION
    catalyst.mOREcoWBEll. IN A
    ;ANSWER
    ;AUTHORITY
    ;ADDITIONAL

Since query is directed to 192.5.6.30, 
this range will be analyzed :
:: 

    ; a.gtld-servers.net.
    RANGE_BEGIN 0 100
	    ADDRESS 192.5.6.30

It has a single entry, which requires "opcode qtype qname" field list to be compared.
Opcode and qtype fields are the same as fields in incoming query.
Let's compare qname.
ENTRY datablock :
::

  SECTION QUESTION
  CATALYST.MORECOWBELL. IN A

Incoming query :
::

  ;QUESTION
  catalyst.mOREcoWBEll. IN A

So, qname also the same. All fields matches and Python server sends answer 
derived from this entry :
::

    id 58167
    opcode QUERY
    rcode NOERROR
    flags QR AA
    edns 0
    payload 1280
    ;QUESTION
    cAtaLyst.MoRECowBEll. IN A
    ;ANSWER
    CATALYST.MORECOWBELL. 3600 IN A 10.20.30.40
    ;AUTHORITY
    CATALYST.MORECOWBELL. 3600 IN NS a.gtld-servers.net.
    ;ADDITIONAL

Here Python found new address 10.20.30.40 and starts listening.
Next queries and answers :

::

    [iter]   <= referral response, follow
    [plan]   plan 'a.gtld-servers.net.' type 'AAAA'
    [resl]     => using root hints
    [resl]     => querying: '193.0.14.129' score: 54 zone cut: '.' m12n: 'A.Gtld-sERverS.nEt.' type: 'AAAA'


query; Resolver ---> Python (193.0.14.129)
::

    id 13810
    opcode QUERY
    rcode NOERROR
    flags 
    edns 0
    payload 1452
    ;QUESTION
    A.Gtld-sERverS.nEt. IN AAAA
    ;ANSWER
    ;AUTHORITY
    ;ADDITIONAL

answer; Python ---> Resolver
::

    id 13810
    opcode QUERY
    rcode NOERROR
    flags QR
    edns 0
    payload 1280
    ;QUESTION
    A.gTld-serveRS.NET. IN AAAA
    ;ANSWER
    ;AUTHORITY
    . 3600 IN SOA bla. bla. 1 2 3 4 5
    ;ADDITIONAL


at this point Resolver returns answer to query from STEP 1 QUERY.

::

    [iter]     <= rcode: NOERROR
    [ pc ]     => answer cached for TTL=900
    [ rc ]   => satisfied from cache
    [iter]   <= rcode: NOERROR
    [resl] finished: 4, queries: 2, mempool: 16400 B


::

    opcode QUERY
    rcode NOERROR
    flags QR RD RA
    edns 0
    payload 4096
    ;QUESTION
    catalyst.morecowbell. IN A
    ;ANSWER
    catalyst.morecowbell. 3600 IN A 10.20.30.40
    ;AUTHORITY
    ;ADDITIONAL

Now STEP 10 will be performed. Is has a single entry which contains 
**MATCH all** clause. **MATCH all** means set of dns flags must be equal and 
all sections presented in ENTRY must be equal to ones in answer. 
Incoming answer has next flags were set: **QR RD AA**. ENTRY datablock contains 
**REPLY QR RD RA NOERROR** clause. As we see, flags set is equal. Also, we can 
see equality of question and answer sections of both dns messages.

So, Python got expected answer and test is passed.

