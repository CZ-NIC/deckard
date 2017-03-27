module Deckard =
  autoload xfm

let del_str = Util.del_str

let space = del /[ \t]+/ " "
let tab = del /[ \t]+/ "\t"
let ws = del /[\t ]*/ ""
let word = /[^\t\n\/#; ]+/

let comment = del /[;#]/ ";" . [label "comment" . store /[^\n]+/]

let eol = del /([ \t]*([;#][^\n]*)?\n)+/ "\n" . Util.indent
let comment_or_eol =  ws . comment? . del_str "\n" . del /([ \t]*([;#][^\n]*)?\n)*/ "\n" . Util.indent


(*let comment_or_eol = [ label "#comment" . counter "comment" . (ws . [del /[;#]/ ";" . label "" . store /[^\n]*/ ]? . del_str "\n")]+ . Util.indent
*)


let domain_re = (/[^.\t\n\/#; ]+(\.[^.\t\n\/#; ]+)*\.?/ | ".") - "SECTION" (*quick n dirty, sorry to whoever will ever own SECTION TLD*)
let class_re = /CLASS[0-9]+/ | "IN" | "CH" | "HS" | "NONE" | "ANY"
let domain = [ label "domain" . store domain_re ]
let ttl = [label "ttl" . store /[0-9]+/]
let class = [label "class" . store class_re ]
let type = [label "type" . store ((/[^0-9#;\n \t][^\t\n\/#; ]*/) - class_re) ]
let data = [label "data" . store /[^\n\t ;#][^\n;#]+[^\n\t;# ]/]

let ip_re = /[0-9a-f.:]+/


let match_option = "opcode" | "qtype" | "qcase" | "qname" | "subdomain" | "flags" | "rcode" | "question" | "answer" | "authority" | "additional" | "all" | "TCP" | "ttl"
let adjust_option = "copy_id" | "copy_query"
let reply_option = "QR" | "TC" | "AA" | "AD" | "RD" | "RA" | "CD" | "DO" | "NOERROR" | "FORMERR" | "SERVFAIL" | "NXDOMAIN" | "NOTIMP" | "REFUSED" | "YXDOMAIN" | "YXRRSET" | "NXRRSET" | "NOTAUTH" | "NOTZONE" | "BADVERS"
let step_option = "REPLY" | "QUERY" | "CHECK_ANSWER" | "CHECK_OUT_QUERY" | /TIME_PASSES[ \t]+ELAPSE/

let mandatory = [del_str "MANDATORY" . label "mandatory" . value "true" . comment_or_eol]
let tsig = [del_str "TSIG" . label "tsig" . space . [label "keyname" . store word] . space . [label "secret" . store word] . comment_or_eol]

let match = (mandatory | tsig)* . del_str "MATCH" . [space . label "match" . store match_option ]+ . comment_or_eol
let adjust =  (mandatory | tsig)* . del_str "ADJUST" . [space . label "adjust" . store adjust_option ]+ . comment_or_eol
let reply =  (mandatory | tsig)* . del ("REPLY" | "FLAGS") "REPLY" .  [space . label "reply" . store reply_option ]+ . comment_or_eol


let question = domain . tab . (class . tab)? . type . comment_or_eol
let record = [seq "record" . domain . tab . (ttl . tab)? . (class . tab)? . type . tab . data . comment_or_eol]

let section_question = [ label "question" . del_str "SECTION QUESTION" .
                       comment_or_eol . question? ]
let section_answer = [ label "answer" . counter "record" . del_str "SECTION ANSWER" .
                       comment_or_eol . record* ]
let section_authority = [ label "authority" . counter "record" . del_str "SECTION AUTHORITY" .
                          comment_or_eol . record* ]
let section_additional = [ label "additional" . counter "record" . del_str "SECTION ADDITIONAL" .
                           comment_or_eol . record* ]
let sections = section_question? . section_answer? . section_authority? . section_additional?

let raw = [del_str "RAW" . comment_or_eol . label "raw" . store word  ] . comment_or_eol

let normal = (match . (adjust . reply? | reply . adjust?)? | adjust . (match . reply? | reply . match?)? | reply . (match . adjust? | adjust . match?)?) . (mandatory | tsig)* . sections

(*let normal = ((match | adjust | reply | mandatory | tsig)* . sections)*)

let entry = [label "entry" . del_str "ENTRY_BEGIN" . comment_or_eol . ( normal | raw )? . del_str "ENTRY_END" . eol]

let single_address = [ label "address" . space . store ip_re ]

let addresses = [label "address" . counter "address" . [seq "address" . del_str "ADDRESS" . space . store ip_re . comment_or_eol]+]

let range = [label "range" . del_str "RANGE_BEGIN" . space . [ label "from" . store /[0-9]+/] . space .
            [ label "to" . store /[0-9]+/] . single_address? . comment_or_eol . addresses? . entry* . del_str "RANGE_END" . eol]

let step = [label "step" . del_str "STEP" . space . store /[0-9]+/ . space . [label "type" . store step_option] . [space . label "timestamp" . store /[0-9]+/]? . comment_or_eol .
           entry? ]

let config_record = /[^\n]*/ - ("CONFIG_END" | /STEP.*/ | /SCENARIO.*/ | /RANGE.*/ | /ENTRY.*/)

let config = [ label "config" . counter "config" . [seq "config" . store config_record . del_str "\n"]* . del_str "CONFIG_END" . comment_or_eol ]

let guts = (step | range )*

let scenario = [label "scenario" . del_str "SCENARIO_BEGIN" . (space . store /[^ \t\n#;][^\n#;]+[^\t\n #;]/)? . comment_or_eol . guts . del_str "SCENARIO_END" . eol]

let lns = config? . scenario

(* TODO: REPLAY step *)
(* TODO: store all comments into the tree instead of ignoring them *)

let filter = incl "/home/stepan/nic/deckard/sets/resolver/*.rpl"

let xfm = transform lns filter
