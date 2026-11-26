# Labelreef

Labelreef runs authoritative DNS zones on Linux loopback. It serves UDP and TCP queries, publishes primary edits, synchronizes secondary zones by AXFR or IXFR, and replaces the active zone routing table atomically. The examples use the reserved `lab.test.` zone and documentation addresses.

## Run the two-node demonstration

Use Go 1.23 or newer and Bash. The Go module uses the standard library.

```sh
mkdir -p bin
go build -trimpath -o bin/labelreef ./cmd/labelreef
bash scripts/demo.sh bin/labelreef
```

The demo copies the example configurations and seeds into a temporary directory, starts a primary and a secondary, and asserts their socket responses. It tests v1 round trips, UDP truncation and TCP retry, initial AXFR, IXFR through `4294967295 → 0`, retention fallback, parent referral after child-zone removal, and secondary restart. Example ports are DNS `15353` and `15354`, and HTTP control `18053` and `18054`. Set `LABELREEF_DIG` to a BIND `dig` executable to run independent BIND client checks during the demo.

## Operate a node

```sh
bin/labelreef check -config examples/primary.json
bin/labelreef serve -config examples/primary.json
```

From a separate terminal:

```sh
bin/labelreef query -address 127.0.0.1:15353 www.lab.test. A
dig @127.0.0.1 -p 15353 +norecurse www.lab.test. A
dig @127.0.0.1 -p 15353 +tcp lab.test. AXFR
bin/labelreef ctl -address 127.0.0.1:18053 status
bin/labelreef ctl -address 127.0.0.1:18053 edit examples/edits/to-4294967295.json
```

Start `examples/secondary.json` in its own process and drive replication with `ctl -address 127.0.0.1:18054 sync lab.test.`. The reply reports the transfer kind, serial, generation and whether the active snapshot changed. `ctl status` includes live TCP transfer positions and the last 32 terminal outcomes. `ctl export lab.test.` writes the active zone as canonical v1 JSON. Use `compare` on the two exports to check all records and their TTLs, including when the SOA serials agree.

`ctl reload` and SIGHUP read the configured file again. Write a replacement file beside the live configuration and rename it into place before reloading. A valid replacement activates all candidate routes at once. Listener, timeout and state-directory settings take effect on daemon restart. A primary seed initializes a zone when it has neither live nor durable data. Use `ctl edit` for record-level changes and `ctl publish` for a full newer primary zone. A secondary stays inactive until it loads a seed, durable snapshot, or completed transfer.

The service accepts numeric loopback listeners and transfer sources. The control interface is HTTP on a separate loopback port and accepts the daemon's literal host and port plus `X-Labelreef-Control: 1`. Edit and publish take JSON bodies. The intended deployment is a trusted local environment. Synchronization is initiated on demand and all content is unsigned. EDNS(0) negotiates UDP budgets. Supported stored records are A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, DNAME, DS and CAA. Zone selection uses the longest active suffix, with parent authority for DS at a delegation. Referrals carry in-zone address records for their name servers. A DNAME redirects strict descendants: the answer carries the original DNAME and a synthesized CNAME built from the target suffix, while a query for the DNAME owner itself is never synthesized. A delegation encountered first still produces a referral, and a synthesized name longer than 255 octets returns YXDOMAIN with the DNAME in authority and no illegal CNAME.

## File formats

- `examples/zones/lab-v1.json` is the editable v1 seed. The envelope contains `version: 1`, `origin` and `records`. Every record includes `name`, `type`, `ttl` in seconds and presentation `data`. Relative owners and domain-name fields use the origin. `@` selects the apex, and a terminal dot denotes an absolute name. Decimal escapes such as `\046` preserve literal label octets. TXT strings and CAA values can be quoted. `labelreef rewrite FILE` emits canonical v1 JSON and `labelreef inspect FILE` summarizes the zone.
- A v1 edit contains `origin`, `base`, `next`, `remove` and `add`. Every removal identifies an exact record. An edit applies when its base serial matches and its next serial is newer under RFC 1982 arithmetic. A difference of exactly 2³¹ is ambiguous and rejected.
- The state directory holds one v1 JSON file per configured origin that has been published or synchronized. The file name is the SHA-256 of the canonical origin. Each file contains the local generation, canonical v1 zone and contiguous retained deltas. `labelreef state FILE` validates it and reports its record fingerprint, SOA and history. A commit synchronizes a temporary file, renames it and synchronizes the directory. A directory synchronization error after rename is reported in the publication receipt. One daemon owns a state directory.
- The `xfr -trace` command records a v1 transfer using the bytes `LABELREEF-XFR`, a zero byte, and version byte `1`, followed by the request and replies in their original TCP length framing. `replay` uses the same transfer parser. Give both commands `-base FILE` for IXFR. Replay consumes the full recording and checks its final SOA and the absence of trailing bytes.

```sh
bin/labelreef xfr -address 127.0.0.1:15353 -trace lab.xfr lab.test. > received.json
bin/labelreef replay lab.xfr > replayed.json
bin/labelreef compare received.json replayed.json
```

## Implementation and verification

| Path | Entry points |
| --- | --- |
| `zone/` | `New`, `Find`, `DecodeV1`, `EncodeV1` validate and index immutable zones, including empty ancestors and delegation cuts |
| `lookup/` | `Resolve` assembles authoritative data, alias chains, negatives and referrals |
| `serial/` | `Advance`, `Replay.Apply`, `Store.Save` guard transitions and durable history |
| `transfer/` | `Build`, `TransferCursor`, `Receiver.Feed` plan and apply framed AXFR and IXFR |
| `serve/` | `Listen`, `Client.Fetch`, `Capture`, `ReplayTrace` handle the DNS wire and TCP transport |
| `reload/` | `Manager.Reload`, `Edit`, `Publish`, `Sync` publish active generations and route changes |
| `cmd/labelreef/` | Linux daemon, query and operational commands |

A lookup holds one immutable zone. A transfer holds a single snapshot and advances its cursor after each complete frame write. A secondary stages through the terminal SOA and verifies its source and starting entry are still current before publication.

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go test -run '^$' -bench 'Benchmark(DeepName|RRsetEncoding|LargeSync)$' -benchmem ./...
```

Wire goldens and parsed query goldens live under `serve/testdata/`. Native tests control the pre-rename publication boundary, the pre-replacement routing boundary, the second transfer frame and a TCP disconnect within a length-framed message. Benchmarks cover depth-sensitive tree lookup, compressed encoding of a multi-record RRset, and AXFR versus IXFR on a zone with 8,000 generated owners.
