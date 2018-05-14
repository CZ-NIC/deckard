#!/bin/bash
set -o errexit -o nounset

# Below a summary of tests that failed including a reason for the failure.
# It might be wise to move these out of the way before testing with getdns.
# Or provide alternatives.
#
# Tests known to fail can be moved out of the way:
#
# 	mkdir sets/resolver.out-of-the-way; for t in `grep '^##' getdns_run.sh | sed 's/^## //g'` ; do mv sets/resolver/$t sets/resolver.out-of-the-way; done
#
#
# OPT-OUT is INSECURE
# ===================
# These fail because getdns will give answers to proven opt-out NSEC3 spans
# the INSECURE status, but will include the DNSSEC data still:
#
## val_nsec3_b1_nameerror.rpl  val_nsec3_b4_wild.rpl  val_nsec3_b5_wcnodata.rpl
## val_nsec3_b5_wcnodata_nowc.rpl  val_nsec3_noopt_ref.out
#
#
# Dependent on specific unbound configuration
# ===========================================
# These fail because they set specific unbound options in the
# "; config options" section.  We might consider facilitating this in getdns
# at some point.
#
## iter_cycle_noh.rpl  iter_ns_spoof.rpl
#
#
# Knot resolver specific behaviour
# ================================
# These fail because it tests specific behaviour which is not the only "right"
# way to do it correct.
#
## iter_lame_nosoa.rpl
#
#
# Modules
# =======
# These fail because it tests certain modules that getdns does not have (yet).
#
## module_dns64.rpl                  module_policy_pass_deny.rpl
## module_hint_static.rpl            module_policy_rpz.rpl
## module_policy_deny_all.rpl        module_policy_tc.rpl
## module_policy_deny_suff_comm.rpl  module_renumber.rpl
## module_policy_deny_suff_patt.rpl  module_view_addr.rpl
## module_policy_forward.rpl         module_view_tsig.rpl
#
#
# To investigate
# ==============
# These tests don't work, but we need to investigate what's wrong.
#
## iter_cname_badauth.rpl     iter_minim_nonempty.rpl
## iter_escape_bailiwick.rpl  iter_minim_ns.rpl
## iter_formerr.rpl           iter_validate_extradata.rpl
## iter_lame_root.rpl         iter_validate.rpl
## iter_minim_a_nxdomain.rpl  nsec3_wildcard_no_data_response.rpl
## iter_minim_a.rpl           val_nsec3_optout_unsec_cache.rpl

RUNDIR="$(dirname "$0")"
cd "$RUNDIR" && ./run.sh --config configs/getdns.yaml "$@"
