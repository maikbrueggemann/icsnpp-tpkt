module tpkt;

const ports = { 102/tcp };
redef likely_server_ports += { ports };

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:           time    &log;
        uid:          string  &log;
        id:           conn_id &log;
        bytes_orig:   count   &log &default=0;
        bytes_resp:   count   &log &default=0;
        packets_orig: count   &log &default=0;
        packets_resp: count   &log &default=0;
    };

    redef record connection += {
        tpkt_info: Info &optional;
    };

    global log_tpkt: event(rec: Info);
}

function get_info(c: connection): Info {
    if(!c?$tpkt_info) {
        c$tpkt_info = [
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
        ];
    }
    return c$tpkt_info;
}

event zeek_init() &priority=5 {
    Analyzer::register_for_ports(Analyzer::ANALYZER_TPKT, ports);
    Log::create_stream(tpkt::LOG, [$columns = Info, $ev = log_tpkt, $path="tpkt"]);
}

event pdu(c: connection, is_orig: bool, version: int, payload: string) {

    local info = get_info(c);

    if(is_orig) {
        info$bytes_orig += |payload|;
        info$packets_orig += 1;
    } else {
        info$bytes_resp += |payload|;
        info$packets_resp += 1;
    }
}

event connection_state_remove(c: connection) {
    if ( c?$tpkt_info ) {
        Log::write(LOG, c$tpkt_info);
        delete c$tpkt_info;
    }
}
