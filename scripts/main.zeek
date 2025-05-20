module tpkt;

const ports = { 102/tcp };
redef likely_server_ports += { ports };

export {
    redef enum Log::ID += { LOG };

    redef record connection += {
        tpkt_bytes_orig:   count &default=0;
        tpkt_bytes_resp:   count &default=0;
        tpkt_packets_orig: count &default=0;
        tpkt_packets_resp: count &default=0;
    };

    type Info: record {
        ts:           time   &log;
        uid:          string &log;
        orig_h:       addr   &log;
        orig_p:       port   &log;
        resp_h:       addr   &log;
        resp_p:       port   &log;
        bytes_orig:   count  &log;
        bytes_resp:   count  &log;
        packets_orig: count  &log;
        packets_resp: count  &log;
    };

    global log_tpkt: event(rec: Info);
}

event zeek_init() &priority=5 {
    Analyzer::register_for_ports(Analyzer::ANALYZER_TPKT, ports);
    Log::create_stream(tpkt::LOG, [$columns = Info, $ev = log_tpkt, $path="tpkt"]);
}

event pdu(c: connection, is_orig: bool, version: int, payload: string) {
    if(is_orig) {
        c $ tpkt_bytes_orig += |payload|;
        c $ tpkt_packets_orig += 1;
    } else {
        c $ tpkt_bytes_resp += |payload|;
        c $ tpkt_packets_resp += 1;
    }
}

event connection_state_remove(c: connection) {
    local r: tpkt::Info = [
        $ts =     network_time(),
        $uid =    c $ uid,
        $orig_h = c $ id $ orig_h,
        $orig_p = c $ id $ orig_p,
        $resp_h = c $ id $ resp_h,
        $resp_p = c $ id $ resp_p,
        $bytes_orig =   c $ tpkt_bytes_orig,
        $bytes_resp =   c $ tpkt_bytes_resp,
        $packets_orig = c $ tpkt_packets_orig,
        $packets_resp = c $ tpkt_packets_resp,
    ];
    Log::write(tpkt::LOG, r);
}

