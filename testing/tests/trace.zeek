# @TEST-DOC: Test Zeek parsing a trace file through the tpkt analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tpkt.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output

event TPKT::pdu_evt(c: connection, is_orig: bool, version: int, payload: string) {
  print(fmt("Testing tpkt: [orig_h=%s, orig_p=%s, resp_h=%s, resp_p=%s] (version: %d) %s",
	    c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, version, payload));
}
