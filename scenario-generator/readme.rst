DNS test harness test generator
===============================

Description ...

Authors
-------

Filip Široký

Requirements
------------

Software required for generating tests:
 - Docker >= 17
 - Python >= 3.5
    - pypcap >= 1.2.0
    - dpkt >= 1.9.1
    - dnspython >= 1.15.0

Supported resolvers
-------------------
 - bind
 - Knot-resolver

Supported browsers
------------------
 - firefox

TODO:
-----
 - Fix scenario generating to pass
    - If QMIN on - fails, If QMIN off - passes with QMIN on and off
    - With deckard kresd asks for gtld-servers.net. even though he needs only one of subdomains - related to gstatic.com.
    - response missmatch with edna.cz - edna.cz gets ip and NS, also looking for www.edna.cz (posibly fixed)
    - When IP for NS isnt given in additional and resolver asks for A => timeout
    - => MATCH needs to be reworked
 - If more resolvers query '.' (Root) - root servers have to be reworked as Knot-resolver does not query '.'
    - Everything around root should be resolved
 - Add more browsers and resolvers
