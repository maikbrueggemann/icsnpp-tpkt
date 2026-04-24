# ICSNPP-TPKT

Industrial Control Systems Network Protocol Parsers (ICSNPP) - ISO on TCP Packet (TPKT)

## Overview

This plugin provides a protocol analyzer for TPKT (RFC 1006) for use within
Zeek. The analyzer enables Zeek to parse TPKT PDUs over TCP.

## Dependencies

The used version of zeek must support spicy.

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html).

```bash
zkg install https://github.com/DINA-community/icsnpp-tpkt
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly, users will see `ANALYZER_TPKT` under the list of plugins.

If users have ZKG configured to load packages (see `@load packages` in the [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html), this plugin and these scripts will automatically be loaded and ready to go.

## Logging

One dataset is logged for each tcp connection containing the following fields. 

| Field             | Type      | Description                                                       |
| ----------------- |-----------|-------------------------------------------------------------------|
| ts                | time      | Timestamp                                                         |
| uid               | string    | Unique ID for this connection                                     |
| orig_h            | address   | Source IP address                                                 |
| orig_p            | port      | Source port                                                       |
| resp_h            | address   | Destination IP address                                            |
| resp_p            | port      | Destination port                                                  |
| bytes_orig        | count     | Total number of bytes sent as payload from the source             |
| bytes_resp        | count     | Total number of bytes sent as payload from the destination        |
| packets_orig      | count     | Total number of packets/pdus sent as payload from the source      |
| packets_resp      | count     | Total number of packets/pdus sent as payload from the destination |

## License

The software was developed on behalf of the BSI (Federal Office for Information Security)

Copyright (c) 2025-2026 by DINA-Community BSD 3-Clause. [See License](/COPYING)
