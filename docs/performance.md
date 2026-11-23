# Performance measurement and capacity planning

Report filter lookup cost, request latency, client RTT, throughput, and memory separately. Rule count and logged `latency_us` alone do not establish server throughput.

## Request stages

For a typical inbound DNS request, the transport receives/parses the packet, policy identifies the client, filter rules may be evaluated, an allowed answer is resolved or retrieved from cache, and the transport formats/sends the answer. DNSCrypt and QUIC-based protocols add cryptographic processing; the work outside the filter engine can dominate.

The filter data structure compiles domains into a compact automaton rather than scanning every entry. That makes millions of domain rules feasible, but individual rule types such as regex and client-address policy can follow different lookup paths. Always report the rule-type distribution, not only the count.

## Latency metrics

| Metric | What it covers | Common mistake |
| --- | --- | --- |
| Filter lookup time | Domain normalization and classification inside the filter engine | Treating it as total DNS latency |
| Internal request latency (`latency_us`, dashboard average latency) | From the moment the server has the DNS message until the answer is ready to send | Assuming transport decryption, encryption, or the send is included |
| Server processing CPU time | CPU consumed across selected protocol and resolver work | Confusing elapsed time waiting for upstreams with active CPU time |
| Client-observed RTT | Full round-trip from client send to response received | Inferring it directly from the dashboard's `latency_us` |

The Query log's `latency_us` starts when the server has the DNS message: for plain UDP, when the datagram is read from the socket; for TCP, DoT, DoH, DoQ, DoH3, and DNSCrypt, when the transport hands over the decrypted and framed message. It stops when the answer is ready to send. A cache hit, a blocked name, and a local answer are measured the same way, and a query sent upstream includes the wait for the upstream. Transport decryption, TLS/QUIC/DNSCrypt encryption of the answer, the send itself, and network delay are outside the span, so encrypted transports cost more per query than the field shows.

## Benchmark procedure

1. Fix the binary revision, build profile, platform, config, dataset, CPU/memory limit and active listener.
2. Distinguish exact-match block, suffix block, allow exception, no-match, cache hit and cache miss workloads.
3. Warm the expected cache state explicitly; for cold tests, reset it deliberately.
4. Measure QPS, CPU time per query, p50/p95/p99 latency, allocation rate and RSS/PSS together.
5. Repeat runs and alternate baseline/candidate order to detect drift and host-load bias.
6. If comparing other DNS servers, match filter semantics, client transport, caching, dataset and query distribution rather than only rule count.

A test with one repeated blocked name disproportionately rewards caches and branch prediction. A synthetic dataset full of repeated suffixes can compress far better than real community lists. Report both realistic distinct-name distributions and a controlled benchmark that isolates one subsystem.

## Memory during filter updates

For a filter refresh, the old compiled snapshot may coexist with a new builder, temporary downloaded/parsing buffers and a new compiled cache. For a 1GiB VM this peak can matter more than the current idle memory use. Monitor the process tree and cgroup while refreshing, not just afterward.

```sh
systemctl show onetdns -p MemoryCurrent -p MemoryPeak
cat /sys/fs/cgroup/system.slice/onetdns.service/memory.events
cat /sys/fs/cgroup/system.slice/onetdns.service/cpu.stat
```

A service cgroup's `MemoryCurrent` cannot simply be divided by number of filter entries to claim an exact bytes-per-rule data structure cost. It includes other process state and possibly charged file pages. To measure the filter index itself, instrument the index allocations or inspect a controlled minimal process with no other duties.

## Workload-specific bottlenecks

| Observation | Hypothesis to test | Measurement |
| --- | --- | --- |
| DNSCrypt much slower than plain DNS | Crypto dominates small blocked queries | CPU time across complete transport path |
| Cache miss causes high p99 | Upstream wait, timeout, or serial receive loop | Mixed hit/miss workload with per-transport RTT |
| Tail latency rises with client count | Queueing, lock contention, transport state | Queue depths, CPU contention, concurrency sweep |
| Memory peaks on list update | Old/new filter and parser buffers coexist | cgroup peak over refresh interval |
| Dashboard says 10µs but client sees milliseconds | Timer excludes transport/network RTT | Correlated client RTT plus server pipeline span |

## Changes to benchmark

Removing duplicate filter classifications and performing deterministic cheap input checks before expensive cryptographic work can reduce hot-path work. Conversely, replacing simple synchronization with a lock-free design, adding worker queues or switching cache layouts can regress performance or safety. Make changes only with a baseline and correctness tests; an optimization that wins on one synthetic fixture may lose on realistic traffic.

## Benchmark report fields

Include: hardware/VM type and CPU limits, OS, build compiler settings, OnetDNS version, rule count and type distribution, active listeners, upstreams, cache state, concurrency, request mix, QPS, p50/p95/p99, CPU usage, peak memory, and run-to-run variation. Avoid describing a single observed best-case microsecond number as a guaranteed service latency.
