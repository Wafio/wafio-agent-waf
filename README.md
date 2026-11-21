# wafio-agent-waf

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16868/badge)](https://www.bestpractices.dev/projects/16868) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Wafio/wafio-agent-waf/badge)](https://scorecard.dev/viewer/?uri=github.com/Wafio/wafio-agent-waf)

This repository is one part of [WAFio](https://github.com/Wafio/wafio). Start there to install WAFio, to see the releases, or to report a problem when you do not know which part it is in.

The open part of the Wafio WAF agent, written in Rust. It runs on a customer host as a reverse proxy in front of the
applications you protect, and takes its routes, upstreams and rules from the Wafio control plane over mTLS gRPC. It does everything
around detection: routing, body and path limits, rate limits, geo rules, bot checks, IP rules, custom rules, login protection,
upload scan, the challenge, WebSocket limits, the decision events and the control link.

What decides whether a request is an attack is the semantic detection engine, which is not in this repository. The agent asks it
through one small interface, the crate `wafio-engine-api`, and knows no engine by name. Built from this repository alone the agent has
an engine that detects nothing: it proxies, enforces everything else, and marks what it did not inspect (see "Without an engine").
The official agent, `wafio-waf-agent`, is this agent with the engine installed; the private repository wafio-semantic-engine builds it,
in two forms: with the engine linked in, or as this agent plus a library that it loads at start (see "The engine in a library").

## Place in the platform

| Repo | Contents |
|---|---|
| wafio-cp-backend | Go control plane, migrations, `shared/` module |
| wafio-cp-frontend | SvelteKit dashboard |
| **wafio-agent-waf (this repo)** | Rust WAF agent without its detection engine |
| wafio-semantic-engine | the detection engine, and the build of the official agent (private) |
| wafio-agent-host | Go host agent, BPF C |
| wafio-portal | wafio.cloud site and blog (SvelteKit), portal API (Go) (private) |
| uddin-lang-rs | Rust uddin interpreter |
| wafio-release | installers, release bundle layout, release and publish scripts (private) |
| wafio-docs | skills, role agents, specs, findings, plans, ops notes (private) |

The agent speaks the protocol defined in wafio-cp-backend (`shared/proto`). A copy of that `.proto` file is vendored in
`proto/`; see "Protocol file" below.

## Requirements

- Rust 1.95.0, pinned in `rust-toolchain.toml` with clippy and rustfmt; rustup installs it on first use. 1.95 is the
  highest `rust-version` among the locked dependencies, and the workspace `rust-version` in `Cargo.toml` says the same.
  Raise both together when a dependency needs more.
- A Linux host to build and test on. The agent uses `sd-notify` and Unix sockets, and the release builds are
  `linux/x86_64`.
- `docker` on the build host for `scripts/build-dist.sh --container`, which builds a release input; that host needs no Rust.
- `bash` for the scripts, `gitleaks` 8.30.1 for the gate, `go` only for `tools/core-gen`.
- A checkout of uddin-lang-rs next to this one (`../uddin-lang-rs`). The agent runs script rules with its crate `uddin-waf`, which
  `Cargo.toml` takes by path for now. uddin-lang-rs has the tag v0.1.0; a git dependency on a tag replaces the path later.
- No `protoc`: the build compiles the proto file with `protox`.

## Build

```sh
cargo build --release -p wafio-waf-agent          # target/release/wafio-waf-agent-open
scripts/build-dist.sh --container                 # target/dist/: baseline binary, notices, SHA256SUMS, VERSION
scripts/build-dist.sh                             # the same on the host itself, with the host's glibc: development only
```

This repository builds the agent without an engine, and names the binary `wafio-waf-agent-open` (the files of `build-dist.sh` are
`wafio-waf-agent-open-linux-amd64-baseline` and so on), so that it cannot be taken for the official one. The official
`wafio-waf-agent` is built by the private repository wafio-semantic-engine: its `scripts/build-dist.sh` runs the script of this
repository over its own workspace, which adds the engine to the same crates. The flags, the help text and the version stamp are the
same in both. `--features` (a hidden flag) prints the version and the engine the agent would run with. The official binary prints
`engine: wafio-semantic-engine`, and wafio-release `scripts/release.sh` refuses a binary without that name. `wafio-waf-agent-open`
prints `engine: none`, unless a library loads at the path a start would use (see "The engine in a library").

`build-dist.sh` reads these variables so that the other repository can use it: `WAFIO_WORKSPACE_DIR` (the checkout whose Cargo workspace is
built), `WAFIO_BIN_PACKAGE`, `WAFIO_BIN_NAME` and `WAFIO_NOTICES_SCRIPT`. A container build mounts that checkout at `/src` and this one
at `/wafio-agent-waf`, next to each other as they are on the host.

The files that ship are stripped by the script, not by cargo, and the build maps the directories it compiled in to short tokens
(`--remap-path-prefix`: the workspace `w`, this checkout `o`, the cargo home `c`, the toolchain and the standard library `t`,
uddin-lang-rs `u`), so panic locations and `file!()` strings name no build host directory. When the workspace is another checkout, each of
its `crates/*/src` source files becomes `p001`, `p002` and so on in sorted order, so its file names are not in the binary either.
A library built through `WAFIO_LIB_PACKAGE` also leaves an unstripped copy with line tables in `WAFIO_DEBUG_DIR` (default `~/wr/debug`
on the build host, never the output directory), named by its build id, with a `.paths` file that maps the tokens back. The header of
`build-dist.sh` shows how to resolve an address and a panic location with them.

`build-dist.sh` must run on a linux/x86_64 host (`WAFIO_VERSION=v2.0.0 scripts/build-dist.sh --container`).
`WAFIO_VERSION` (default `dev`) is stamped into the agent and sent to the control plane in its Hello message. It builds
the baseline binary (any x86-64 CPU), which is the one a release ships; `scripts/build-dist.sh --container baseline v3` adds an
x86-64-v3 binary that needs AVX2 and dies with SIGILL on an older CPU. Next to the binaries it writes
`NOTICES.txt` (`scripts/gen-notices.py`: the crates the agent links, from `cargo metadata` and the licence files in the
crate sources; the crates it links from other repositories (uddin-lang-rs), the code adapted from other projects, the
copyright lines found only in source headers and the runtime data the agent downloads, from `scripts/notices/`),
`SBOM.spdx.json` (the same crates as SPDX JSON, made by `gen-notices.py --spdx` from the build's own dependency tree, so it holds
no dev-dependency and no build tool), `SHA256SUMS` of the binaries it built and `VERSION` with the stamped version. They go to `target/dist/` of the checkout, not to `build/`, which on a shared build host can be a link
to a directory several checkouts use; `WAFIO_DIST_DIR` overrides it. Release builds do not run on a host
that serves downloads.

`--container` runs the same script inside the AlmaLinux 8 image `quay.io/pypa/manylinux_2_28_x86_64` (glibc 2.28,
gcc 14), pinned by digest in `build-dist.sh`. The checkout is mounted read-only, rustup installs the Rust version of
`rust-toolchain.toml` into `WAFIO_CACHE_DIR` (default `~/.cache/wafio-dist`, which also keeps the downloaded crates), and
the objects go to `<target>/container`, apart from a host build. The binary therefore names glibc 2.28 at most and
starts on any distribution with glibc 2.28 or newer, where a build on Ubuntu 24.04 names glibc 2.39. `WAFIO_DOCKER_ARGS`
adds docker options on a shared host (`--cpuset-cpus 10,11,12 --cpus 3 --memory 8g`), and `CARGO_BUILD_JOBS` caps the jobs.
Two builds of the same source are not byte for byte equal: `const-random`, which `ahash` uses, draws random constants when it is compiled.

`--musl` builds a fully static binary instead (static-pie, no glibc, no loader) in the pinned image `rust:1.95.0-alpine3.23`,
into `target/dist-musl` as `wafio-waf-agent-open-linux-amd64-baseline-musl`. It is an option, not what a release ships. What
differs from a glibc build: names are resolved by musl's own resolver, which has no NSS and applies the search domains of
`resolv.conf` only to names with fewer dots than `ndots` (with the default `ndots:1`, the upstream `http://app.sub` does not
find `app.sub.corp.example` from `search corp.example`, where glibc does); and `scripts/gen-notices.py` does not yet add the
notices of musl and libunwind that a static binary carries. (`wafio-allocs`, a tool of the engine repository, does not build
either, because it calls glibc's `backtrace`.)

## Test

```sh
scripts/ci-local.sh
```

In order: agent-material check (`scripts/check-ai.sh`), secret scan (`gitleaks`), proto copy check
(`scripts/sync-proto.sh --check`), notices (`scripts/gen-notices.py`), advisories, the test certificates,
`cargo fmt --all --check`, `cargo clippy --locked --workspace --all-targets --features wafio-waf-agent/test-tls -- -D warnings` and
`cargo test --locked --workspace --features wafio-waf-agent/test-tls`. In a copy of the tree without `.git` the gate skips the agent-material check
and scans the files for secrets instead of the history; run `scripts/check-ai.sh` in the checkout then.

The feature `test-tls` of `wafio-waf-agent` lets `WAFIO_TEST_TLS_DIR` name the key directory, so that the tests of the binary can use a
directory that the user they run as owns (the fixed path needs the user of the unit); `tests/tls_bundle.rs` and `tests/control_plane.rs`
are built only with it. No release build enables it.

`scripts/pebble.sh up` starts Pebble, the ACME test server of Let's Encrypt, and its DNS server in two containers pinned by digest
(it needs docker; see the header of the script). `eval "$(scripts/pebble.sh up)"` sets `WAFIO_PEBBLE_DIRECTORY` and the settings that go
with it, and the tests of `tests/tls_bundle.rs` whose names start with `pebble` then order certificates from it with the real
binary and a fake control plane: with TLS-ALPN-01, with HTTP-01 on the redirect listener, and with HTTP-01 on the HTTPS listener behind
something that sends port 80 to HTTPS. Without `WAFIO_PEBBLE_DIRECTORY` they print that they are skipped. `scripts/pebble.sh down` stops
the containers. The gate does not run them. Run them after `scripts/gen-test-certs.sh`, one at a time:
`cargo test -p wafio-waf-agent --features test-tls --test tls_bundle pebble -- --test-threads=1 --nocapture`.

The gate needs nothing from the private repository. The loader's file checks are tested here (`crates/engine-loader`) and the
encodings with random and damaged buffers of a fixed seed (`crates/engine-abi/tests`); loading a real library, the failure cases that need
one (another interface version, a failing init, a panic in a scan) and the comparison of the two forms are tested in wafio-semantic-engine. The tests run with the engine that detects nothing, or with
`crates/engine-fake`, which takes the text `wafio-test-sql` for an SQL injection and `wafio-test-xss` for a cross-site
scripting attempt: enough to drive verdicts, modes, log-only engines, decision events and WebSocket closes. What real
detection finds, and the regression snapshot of its verdicts, are tested in wafio-semantic-engine.

The test certificates and keys in `crates/control/tests/fixtures` are not in git. `scripts/gen-test-certs.sh` makes
a set with openssl (an authority, a server certificate for localhost and two client certificates), and `ci-local.sh`
runs it when a file is missing. The control-plane link tests and the agent integration tests need them; run the
script once before `cargo test` by hand.

The rules documents the reader of `engine-rules` is replayed against (`rules_golden`) and the bundle scenarios
(`crates/waf-agent/tests/fixtures/bundle_golden.jsonl`) hold no verdict of an engine. `bundle_golden` is rewritten with
`WAFIO_WRITE_SNAPSHOT=1 cargo test -p wafio-waf-agent --test bundle_golden`; the other golden data is written by
`scripts/make-snapshot.sh` of wafio-semantic-engine.

Tests that compare against the control plane's Go code through a dump skip when the variable of their dump is unset:
`geo_differential` (`GODUMP_GEO`, the databases in `GEO_DB_DIR`), `net_differential` (`WAFIO_GONET_ORACLE`),
`pattern_differential` (`WAFIO_REGEXP_ORACLE`) and the websocket rules check of `wafio-domain` (`GODUMP_WS`). Go tests in
wafio-cp-backend (`shared/geo`, `internal/engine`, `internal/domain`) write the dumps, each when its `*_OUT` variable names a file.
The script replay (`crates/waf-agent/tests/script_rules.rs`) runs the recorded cases of `build/regression/script-golden.jsonl`
(`WAFIO_SCRIPT_GOLDEN` names another file) through the agent's runner, and skips when the file is missing. The file is not in git:
`scripts/make-snapshot.sh` of wafio-semantic-engine writes it, with the results of this runner, from recorded script cases.

The black-box suites that start an agent binary and drive it over HTTP and gRPC live in wafio-cp-backend
(`internal/conformance/blackbox`). They take the binary from `WAFIO_AGENT_BIN`, so they run against this agent too.

`WAFIO_CARGO_PROFILE` (default `conformance`, the release profile without LTO) picks the profile of clippy and the tests.

## Hello features

The agent reports in `Hello.features`: `script_rules` (it runs script rules in its own process), `maintenance_mode` (it
serves the maintenance page, see below), `tls_certificates` (it takes `CertificateInstall` and sends `CertificateStatus`, see
"HTTPS from the agent") and, only when no engine is installed, `no_semantic_engine`. The official agent never sends the last
one. `tls_certificates` goes in every Hello of an agent that could use its key directory at start; without one the start logs a
warning that names the directory and the cause, the feature is left out, and the `tls` objects of the bundles are ignored. The
control plane ignores names it does not know.

## Maintenance mode

An app whose bundle entry carries a `maintenance` object with `enabled: true` answers every request itself with status 503, before
any other step: no inspection, no challenge, no upstream contact, and it is not recorded as a decision. This holds for every
method, for a WebSocket handshake (refused, nothing is upgraded), for HEAD (headers only) and in monitor mode.

The answer is decided from the request head. The body is not read into memory and not forwarded, so an upload over the body limit
gets 503, not 413, and `Expect: 100-continue` gets the final 503 with no `100 Continue` first. Only the bytes that arrived with the
head, at most the header buffer, are held. A request with no body or with `Content-Length: 0` keeps its connection, and the next
pipelined request is served. A request with a body (`Content-Length` above 0, chunked, or `Expect: 100-continue`) gets
`Connection: close`: the agent writes the answer, closes its side and drains at most 256 KiB or one second of what the client still
sends, so the client can read the answer. Requests pipelined behind such a body are dropped; the client may retry them. Draining an
unknown body to keep the connection would buy nothing during maintenance.

- `allow_ips`: IP addresses or CIDR ranges. A request from one of them, judged by the client IP after trusted-proxy handling, gets
  the site and runs the full normal pipeline.
- `allow_paths`: a request whose decoded, dot-resolved path (the path the upstream receives) equals an entry, lies below it
  (`/healthz` covers `/healthz/x`, not `/healthzx`), or starts with an entry that ends in `/` gets the site. The match is
  case-sensitive. A path that holds `;` must also match with the path parameters removed from it and from the entries,
  because servlet containers route `/healthz/..;/admin` to `/admin`. An entry of `/` lets every path through.
- The format follows the `Accept` header: `text/html` gets HTML, else `json` gets JSON, else `xml` gets XML, else HTML. Only the
  HTML page can be replaced (`custom_html`). `{{WAFIO_MESSAGE}}` is the message, or a default text, escaped for the format.
  `{{WAFIO_END_TIME}}` is the expected end as `YYYY-MM-DDTHH:MM:SSZ` while it lies ahead, else empty. The bodies are built once when
  the bundle is applied (HTML, JSON and XML, each with the end time shown and hidden), so a request only picks one and copies it.
  Each `{{WAFIO_MESSAGE}}` in a custom page becomes the escaped message (up to 2,500 bytes for 500 characters), so a 64 KiB page that
  repeats it thousands of times makes a body of up to about 10 MB, held twice while an end time is set and copied for every answer.
- While the end time lies ahead the answer carries `Retry-After`, counted per request from the clock. A past end time counts as no end
  time. The agent never ends maintenance by itself: the control plane has to send a bundle without the object.
- Every answer carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Vary: Origin`.

### Open connections

Turning maintenance on, or changing `allow_ips` or `allow_paths`, ends what is already open for the clients that are not allowed
(judged by the client and path of the original request). Other apps on the agent are not touched. Turning it off does nothing to
connections.

- A WebSocket session gets a close frame with code 1001 and the reason `Maintenance` on both sides, then both connections are cut
  without waiting for the peers' replies. A close frame that cannot be written within two seconds, or that would follow a message
  the relay was still writing to that side, is left out, and that side sees only the connection close. A session of an allowed
  client or path keeps running, until a change of the lists takes that permission away.
- A streamed response with `Content-Type: text/event-stream` ends the same way for a client that is not allowed: the closing chunk
  `0\r\n\r\n` when the response is chunked, then the connection closes, and the upstream connection is dropped, not reused. An
  event stream is open-ended, like a session, and would keep the backend busy through the whole maintenance window.
- Every other streamed body (a chunked download, an export, a streamed API answer) finishes. It is a request that started before
  maintenance; cutting it hands the visitor a broken file, and the upstream timeout already ends a stalled one. Answers with a
  `Content-Length` are read whole before they are sent and are not affected. A request that is still waiting for its answer (a long
  poll, for example) gets it, within the app's upstream timeout.
- When the listener stops, which a reload (SIGUSR2) and a shutdown do and removing the app from the bundle does, every open WebSocket
  session gets close 1001 with the reason `Going away`. After a reload the old process never learns of a later bundle, so it closes
  its sessions at once; clients reconnect to the successor, which holds the current bundle and answers the handshake with 503 while
  maintenance is on. Without this the 30 second drain would have cut them with no close frame. Event streams are not ended when the
  listener stops: after a reload the old process keeps them until they end or the drain cuts them, and maintenance turned on in
  that window does not reach them, since the old process receives no bundle after the handover. Ending every event stream at every
  reload would cut streamed answers (an API that answers with `text/event-stream`) that finish within the drain.

### Browser apps on another origin

The 503 carries CORS headers, so a browser app can read it instead of seeing a network error. Only the maintenance answer does;
requests that bypass maintenance and apps that are not in maintenance are untouched.

- A valid `Origin` (`null`, or `scheme://host[:port]`, printable ASCII, no comma, at most 256 bytes, exactly one `Origin` line) is
  reflected in `Access-Control-Allow-Origin`, with `Access-Control-Allow-Credentials: true` and `Access-Control-Expose-Headers:
  Retry-After`. The body is public text (the message and the end time), no cookie is set and no upstream data is involved, so reading
  it with credentials from any origin leaks nothing.
- A preflight (`OPTIONS` with a valid `Origin` and an `Access-Control-Request-Method` that is a token of at most 32 bytes) gets 204 with
  no body: the origin, the requested method, the requested headers when they are header names separated by commas (spaces around them
  allowed) within 1024 bytes, `Access-Control-Max-Age: 0`, `Cache-Control: no-store` and `Vary` for the three request headers. It carries no
  `Access-Control-Allow-Credentials`, and it is counted like any other maintenance answer. The agent cannot link a preflight to the
  request after it, and maintenance may end in between: an approval that allowed credentials, or stayed in the browser's cache, would let
  a page on another site send a credentialed request that needs a preflight into the upstream. The remaining limit: such a request still
  fails in the browser during maintenance. Without credentials the approval can still let one request through to the upstream when
  maintenance ends between the preflight and that request. It carries no cookie and no HTTP authentication, so it can do nothing a
  direct request from anywhere could not, except come from the visitor's address. No `Access-Control-Allow-Private-Network` is sent.

The agent ignores keys it does not know, drops an entry it cannot read (an end time that is not exactly `YYYY-MM-DDTHH:MM:SSZ`,
an address that is not an IP or CIDR range, a path that does not start with `/`) with one log line each, and never fails the app over
them. The counter `wafio_waf_maintenance_responses_total` counts the answers, preflights included.

The agent accepts control messages of at most 4 MiB, a bundle included (tonic's limit, set explicitly). The control plane keeps a bundle
under it; a larger one would end the stream and the agent would keep its last bundle.

## FastCGI upstreams

An app whose upstream starts with `fcgi:` talks FastCGI to PHP-FPM, over a Unix socket (`fcgi:unix:/run/php/php-fpm.sock`) or
TCP (`fcgi://127.0.0.1:9000`). The bundle keys `fcgi_doc_root` and `fcgi_index` say where the scripts are.

The option `fcgi_keep_conn` is off by default, as nginx without `fastcgi_keep_conn`. The agent then opens one connection for each
request, sends FCGI_BEGIN_REQUEST without FCGI_KEEP_CONN and closes the connection after the reply. The open connections are still
limited to `max_conns` of the app's `proxy_config`. The control plane sends the bundle key `fcgi_keep_conn: true` only when the
option is on for the app, and an agent that does not know the key ignores it.

With the option on, the agent sends FCGI_KEEP_CONN, puts the connection back in a pool after the reply and reuses the newest idle one
until it has been idle for `idle_conn_ms`. A kept connection pins one PHP-FPM worker while it is open.

Turn it on only when PHP is at least 8.2.36, 8.3.37, 8.4.28 or 8.5.13 for its 8.2, 8.3, 8.4 or 8.5 series. On any other series leave
it off. PHP-FPM before these releases runs request body bytes that the application left unread as a second request on a kept
connection (CVE-2026-129289). The agent takes two precautions on a kept connection: every request carries a random id, and a reply
record with another id breaks the connection and fails the request with 502; a connection with input waiting is closed instead of
pooled or reused. These checks narrow the risk. They do not replace the PHP update.

With the option on or off, the agent never sends a request again after a write to PHP-FPM failed: the script may already be running,
and a second copy could run a POST twice.

## Script rules

The agent runs the script rules of a bundle with the uddin interpreter (crate `uddin-waf`), in its own process. There is no
second process and no flag. When a bundle is applied, every enabled rule of every app is compiled once. A rule that does not
compile (a syntax error, a builtin outside the sandbox profile, a source over 64 KiB, a `break` or `continue` outside a loop)
is dropped with a log line and counted in `script_rules_rejected_total`; the others are kept.

A request runs the rules of its app in the order priority, creation time, id, on the thread that handles the request, each
under the sandbox limits of the profile and the script deadline (5 ms) and all under the budget of the request (15 ms). The
first `block` or `log` ends the run, so does an `allow` unless a rule before it did not finish. A rule that fails with a
runtime error, hits a limit, passes the deadline, panics or finds the budget spent did not finish: the verdict is LOG at
worst, the coverage says `script_error` (a runtime error) or `script_timeout` (anything else), and a gap the request itself
causes (an error, a limit, a panic) may be raised to a block by `on_uninspected: block`, while a gap that load causes (the
deadline, the budget) never is. Nothing a script does changes the request: the variables are copies and the `waf_*`
builtins only read.

## Without an engine

An agent that has no engine linked in and loads no library installs no engine. It proxies and enforces everything that is not semantic detection, and
every scan of the engine boundary finds nothing. It says so: the Hello carries `no_semantic_engine`, and each decision that reaches
the stage where the engines would run lists `engine_absent` in its `coverage` text, next to the `engine_disabled:<key>` marks. The mark is
informational. It is not a coverage gap, never raises an allow to a log line or a block, and is not counted in the partial-coverage
metric. The detector switches below are still read from the rules documents, and the baseline of query parameters is not kept.

## The engine boundary

`crates/engine-api` holds what the agent and an engine agree on: the scan configuration (`SemanticConfig`, the policy of each detector,
the SSRF blocklist), the reasons of the findings and their CWE and ATT&CK labels, the coverage marks (`ScanCoverage`), and the `Engine`
trait. The agent never names an engine: it calls `wafio_engine_api::engine()`, which is the engine that detects nothing until a binary
calls `wafio_engine_api::install` once, before it starts. The trait has one call per request (`scan_request`: the request, the
configuration with the policy, the path override and the tuning skips already applied, in; the strongest finding, where it sat and
what was not covered, out), one per WebSocket frame (`scan_value`, after `frame_fields` has cut the payload into values), and a few small ones: the GraphQL
batch limit, which detectors a configuration switches off, where an undecided verdict points, whether a header value looks hostile (for
the snippets of a decision event), the stack budget of a detection thread, the engine's counters, the JA4 fingerprints it ships for the
bot check, and a new baseline of query parameters. An engine is a static object behind one pointer, so the
boundary adds one indirect call per request and copies nothing.

A finding has a tier: strong (the decision is a BLOCK) or weak (a LOG). No score, threshold, base score or score scale
crosses the boundary. The decision event keeps a `score` for the wire and for old dashboards, and the agent fills it from the
reason and the tier (`decision_score` in `engine-api`): a weak detection is 115, a strong one is the number of its category
(SQLi, LFI, SSRF, XXE, NoSQLi and LDAP 180, PHP, Python, Java, SSTI and deserialization 190, command injection and JWT 200,
prototype pollution 185, everything else 150). Nothing reads that number for a verdict; an engine also uses it to order two
findings of one tier, so that the same one is reported on every run.

## The engine in a library

The engine can also live in a shared library, `libwafio_semantic_engine.so`, that the agent loads at start. The private repository
wafio-semantic-engine builds it from the same engine code as the official agent with the engine linked in. The crate
`wafio-engine-loader` is the only code of the agent that opens a library or calls into it; the rest of the agent sees the `Engine`
trait, as before.

The interface. Rust has no stable ABI, so no Rust type crosses the boundary. `crates/engine-abi` holds what does: the `extern "C"`
functions (`crates/engine-abi/include/wafio_engine.h`), `#[repr(C)]` structs of pointers, lengths and integers, and byte buffers in
documented encodings (`wire.rs` for results, `config.rs` for the scan configuration). The first call is
`wafio_engine_interface_version`, the second `wafio_engine_identity` (the engine name, the build version, and the revision of
`wafio-engine-api` the library was built against), and `wafio_engine_init` comes before anything else. A request goes over as borrowed
slices, so its body is not copied. The scan configuration of an application (with the path override and the tuning skips applied)
is handed over once, as a row of 29 words, and every scan names the handle the library returned for it; the agent finds the handle of a
configuration by comparing rows, and keeps the last eight of each thread without a lock. A result is written into a 4 KiB buffer
of the calling thread. A scan that finds nothing is five bytes and allocates on neither side. A result that does not fit comes back
in a buffer the library allocated, which the agent returns with `wafio_engine_buffer_free`. Memory is never freed by the allocator
of the other side: the library uses mimalloc, as the agent does, and each has its own heap.

The version rule. `INTERFACE_VERSION` is one number. A change of a layout, a symbol, an encoding or the meaning of a field raises it, and the
agent loads a library of exactly its own number: there is no range, because the agent and the library ship in one bundle. A library of another
number is not loaded, and the log line says both numbers. The number is 2: version 2 took the score thresholds, the base scores and
the tuning multiplier out of the scan request and the configuration row, and a finding carries a tier where it carried a score.

Where the library comes from. `--engine-lib` (`WAFIO_ENGINE_LIB`), default `/usr/lib/wafio/libwafio_semantic_engine.so`. Nothing is
searched: not `LD_LIBRARY_PATH`, not the working directory, and a relative path is refused. Only an agent with no engine linked in
looks for a library; the official agent with the engine linked in ignores the flag and says so.

What is checked before loading. Loading runs the code of the file, so who can write it decides who can run code in the agent:

1. the path is absolute;
2. every directory above the file, as the path is written and as it resolves, is owned by root and not writable by group or others;
3. the file, opened without following a link, is a regular file owned by root and not writable by group or others;
4. `<path>.sha256` passes the checks of 3 and starts with the SHA-256 of the library in hex, and the bytes of the library hash to it (the
   installer writes this file from the checksum in the signed bundle);
5. the file is an ELF shared object whose segments and section headers lie inside the file, because a library that was cut short and then
   checksummed kills the process with SIGBUS when the dynamic loader reads it.

The library is then opened through the file descriptor that was checked (`/proc/self/fd/N`), so a file replaced after the checks is
not the one that runs. It is loaded with `RTLD_NODELETE` and kept for the life of the process. After the version, the agent reads the identity, resolves every
symbol and calls `wafio_engine_init`, which also scans a probe string to start the lazy tables of the engines.

When it does not load. A missing file, a failed check, an interface version the agent does not know or an init that fails: the agent logs
one line that names the file and the reason, and runs as it does without an engine (`no_semantic_engine` in the Hello,
`engine_absent` in the decisions). It is never half loaded: the engine is installed only after every step passed. When a scan
fails at run time (a panic caught inside the library, or a result the agent cannot read), the request is allowed unanalysed through the
recover path of `analyze` and counted in `recovered_panics`, as any analyzer fault is; the engine stays installed, because a panic on one
request must not turn detection off for all of them. The calls that have no such path (frame fields, a value scan, the
GraphQL limit, the header check, the match source) return what an engine that finds nothing returns, and are logged when their count is a power of two.

Required. `WAFIO_ENGINE_LIB_REQUIRED=1` makes a library that is missing or cannot be used fatal: the agent does not start. The release installers write
it into `/etc/wafio/waf-agent.env`, so a cold start without the library fails, and the log line names the variable. Without it, such a library is the case
above and the agent runs without an engine. `--features` takes the same step as a start, with the same path (the library that was named, else the default),
so it prints the engine the service would run with. When no library is there it prints `engine: none` and exits 0. It fails where a start fails over the
library: the variable is set and the library cannot be used, or a static musl agent was told to load one.

A reload. The successor of a SIGUSR2 reload runs the same start and loads the library itself. If the predecessor ran with a library, it starts the
successor with `WAFIO_ENGINE_LIB_REQUIRED=1`, and a successor that cannot load the library then refuses to start: the predecessor keeps serving, as it does for any
failed handover. The log line says that the process it replaces runs with the library. The installer replaces the library by rename, so a running agent keeps the file it loaded.

musl. A static musl agent cannot load a shared library. Started with `--engine-lib` or `WAFIO_ENGINE_LIB`, it refuses to start with a log line that says so; without
either it runs without an engine. `scripts/build-dist.sh` of this repository refuses to build the library for musl.

Building. `cargo build --release -p wafio-waf-agent` builds the agent here without an engine, whichever way it gets one later. The library, and the two
forms of the official agent (the engine linked in; this agent plus the library), are built by wafio-semantic-engine. The loader uses
`libloading` 0.9.0 (checked against OSV on 2026-11-16: no advisory for any version).

## Run locally

The agent needs a control plane to get its routes from, so there is no static mode. Register a WAF agent in the
dashboard, download its mTLS bundle, then:

```sh
target/release/wafio-waf-agent-open \
  --grpc-server cp.example.test:9090 \
  --client-cert client.crt --client-key client.key --ca-cert ca.crt \
  --agent-name my-agent \
  --geo-country-db /etc/wafio/security-data/geoip/country.mmdb \
  --geo-city-db /etc/wafio/security-data/geoip/city.mmdb \
  --geo-asn-db /etc/wafio/security-data/geoip/asn.mmdb \
  --bot-ua-file /etc/wafio/security-data/user-agents/bot.txt \
  --bot-ja4-file /etc/wafio/security-data/ja4/ja4.txt
```

The listen ports and upstreams come from the control plane. Fetch the security data (GeoIP databases, IP reputation
lists, bot fingerprints, malware hashes) once, and again from time to time. `--dir` defaults to
`/etc/wafio/security-data`; `--maxmind-key` (or `WAFIO_MAXMIND_LICENSE_KEY`) is for the MaxMind databases;
`--profile` is `agent` by default, `--only` picks single components and `--force` downloads again:

```sh
wafio-waf-agent-open fetch-data --dir /etc/wafio/security-data --maxmind-key <key>
```

## Configuration

Flags fall back to `WAFIO_*` environment variables, and the command line wins over the environment. `--engine-lib` (`WAFIO_ENGINE_LIB`) names the
engine library (see "The engine in a library"). Required (the agent stops at
start and names every missing one): `--grpc-server` (`WAFIO_GRPC_SERVER`), `--client-cert`, `--client-key`,
`--ca-cert`, `--agent-name`, `--geo-country-db`, `--geo-city-db`, `--geo-asn-db`, `--bot-ua-file`, and one of
`--bot-ja4-file` or `--bot-ja3-file` (when `--bot-ja4-file` is empty the agent uses the first non-empty `ja4.txt` it finds under
`security-data/ja4/`, `/etc/wafio/security-data/ja4/` and `/usr/local/share/wafio/ja4/`). Optional ones include `--host-key`,
`--state-dir`, `--bundle-cache-max-age` (default `168h0m0s`), the IP reputation and
jail files, `--pid-file` and `--acme-directory` (`WAFIO_ACME_DIRECTORY`, the directory certificates are ordered from for apps
whose source is `acme`; an https address only, the agent stops at start for any other; default
`https://acme-v02.api.letsencrypt.org/directory`, that of Let's Encrypt). `wafio-waf-agent-open --help` lists all of them.

The security data (GeoIP databases, user-agent and fingerprint lists, IP reputation lists, malware hashes) lives in one
directory: `--security-data-dir` (`WAFIO_SECURITY_DATA_DIR`, default `/etc/wafio/security-data`). The control plane
reports what is in it and can ask the agent to refresh it. An install of version 1 set `--crs-default-dir` /
`WAFIO_CRS_DEFAULT_DIR` instead; the agent still reads it (a trailing `/rules`, then `/coreruleset`, then `/crs` is
stripped from the value), logs one warning naming the new setting, and uses the new setting when both are set.

State lives in `--state-dir` (`/var/lib/wafio-waf-agent` under systemd): the last applied bundle, so a restart while
the control plane is down still serves the protected applications, and the challenge secret.

systemd: the unit is wafio-release `deploy/systemd/wafio-waf-agent.service`, the only copy.
It is `Type=notify`, `NotifyAccess=all`, runs the binary from
`/usr/local/bin` with `/etc/wafio/waf-agent.env`, and reloads on `SIGUSR2`:

```sh
systemctl reload wafio-waf-agent    # a successor takes the listening sockets, the old process drains and exits
```

The agent sends `READY=1` after its first bundle (live or cached). The unit runs as the system user `wafio`, keeps
`CAP_NET_BIND_SERVICE` so an app can listen below port 1024, and applies the containment that the header of the
unit file lists, with what stays writable. The Rust
agent has not been started under the unit on a real systemd yet: test a start, a reload and a script rule on a test host
before a production host.

## HTTPS from the agent

By default an app listens on plain HTTP, where its bundle says, and a proxy or load balancer in front of the agent ends TLS. An
app can instead be served over HTTPS by the agent itself. The settings come from the bundle: an app whose entry has a `tls`
object (the control plane sends it while the app is in gateway mode) is served over HTTPS, and an app without one behaves
exactly as before.

```json
{"app_id": "<app id>", "tls": {"listen": "0.0.0.0:443",
  "hosts": ["shop.example.com", "www.shop.example.com"], "redirect_listen": "0.0.0.0:80",
  "source": "uploaded", "certificate_id": "<certificate id>", "leaf_sha256": "<hex>"}}
```

- The agent checks the object as the control plane does, and no stricter. `app_id` (and `certificate_id`) must be a lower-case UUID, as
  they name files. `listen` and `redirect_listen` are an IP address with a port from 1 to 65535 (an IPv6 address in square brackets),
  and differ; `listen` is `0.0.0.0:443` when it is left out. `hosts` are 1 to 100 plain DNS names, trimmed, lower-cased and each
  kept once: no port, no wildcard, no IP address, no trailing dot, no underscore. An object that fails a check refuses the whole
  bundle (`invalid TLS site settings`, with the app and the field in the log), as an invalid route does: the previous bundle stays and
  the control plane sends it again. A `source` that is empty or not known, or an uploaded one with no certificate named yet, is no
  refusal: nothing is served for that app, and a certificate it was served before is dropped with its file. A bundle that cannot
  bind an address of its apps (another program still holds port 443, say) is tried again every minute, for as long as it takes.
  That holds for the cached bundle an agent starts from while the control plane is out of reach, until a live bundle arrives.
- The certificates are files of the key directory, `/var/lib/wafio-waf-agent/tls/` (the unit's `StateDirectory` is its parent; it does
  not follow `--state-dir`). The agent makes it 0700 if it is missing and uses it only when it is a directory, not a link, owned by
  the user the agent runs as; group and other access is cleared and logged. Otherwise the start logs a warning that names the
  directory and the cause, and the `tls` objects are ignored. A file holds one private key and the chain, leaf first
  (`<certificate id>.pem` for an uploaded certificate, `acme-<app id>.pem` for an ordered one), and is 0600. A file is read when a
  bundle is applied (the start, a reload, a new bundle), never through a link and up to 128 KiB. An app is served the file its
  bundle names, if it is there and holds the certificate the bundle names by its leaf; until then, the file it was served before,
  which `state.json` in the same directory remembers across a restart (it holds no key material, and drops the apps that are not in
  the bundle). That holds for a bundle that names a file; one that names none (see above) serves nothing. A certificate file of
  the agent (`<certificate id>.pem`, `acme-<app id>.pem`) that no app of the bundle names and none is served from is removed after
  each applied bundle: once the new certificate is served, the old file goes. Any other file in the directory stays. The agent
  sets `PR_SET_DUMPABLE` to 0, so a crash leaves no core dump with the keys in it and no other process of the same user can
  attach to it with ptrace.
- One process writes in the key directory: the one that holds an exclusive `flock` on `tls.lock` there. A reload's successor reads
  what the process it replaces wrote, serves it, and writes nothing; it takes the lock once the process it replaces has stopped
  accepting, and then does what it put off (`state.json`, the removal of unused files, which spares a file the other process
  recorded after this one started). It also takes in the orders the other process ended after this one applied its bundle: it serves the
  certificate that process kept and keeps its record of a failed order, with the time of the next try, so a reload in the middle of an
  order does not make a second order for the same names. Files are written under a temporary name, synced and renamed, so a reader sees
  a file whole or not at all.
- An uploaded certificate arrives in a `CertificateInstall`, which the control plane sends to an agent that reported
  `tls_certificates`, when the agent has told it with a status that the bundle names a certificate it does not hold. The install
  holds the apply lock from its first check to the switch of the certificate, so a bundle is never applied in between. The checks
  run in this order, and the first that fails is the answer (`CommandAck.error` is that code and nothing else): the latest applied
  bundle, cached or live, names this app with the source `uploaded` and this certificate id and leaf (`not_in_bundle`); the
  certificate is held already (`ok`, nothing is written); the chain is over 64 KiB or the key over 16 KiB (`too_large`); a block of
  the chain is not a `CERTIFICATE`, the chain has none, or the key text is not exactly one unencrypted `PRIVATE KEY`, `RSA PRIVATE KEY`
  or `EC PRIVATE KEY` block, an `EC PARAMETERS` block beside it being ignored as the control plane ignores it (`bad_pem`); more than
  10 certificates, or a chain that is over 64 KiB once it is written again with lines of 64 characters (`too_large`); the SHA-256 of the leaf is not `leaf_sha256` (`leaf_mismatch`); the TLS library cannot sign with the
  key, which it reads as RSA, ECDSA P-256 or P-384 or Ed25519 (`unsupported_key`); the key does not belong to the leaf
  (`key_mismatch`); the file cannot be written (`write_failed`, which a process that waits for the directory lock also answers, as it
  writes nothing until it has the lock). Then the file is written, key first and the chain after it, both written again from their
  DER, so what is on disk is one key block and the chain whatever text came in; the next handshake gets the certificate and an open
  connection goes on; the certificate it replaces is removed; and `active` is reported. The key is in no log line, no message
  the agent sends, no bundle cache and no heartbeat. The message that carries it, the DER decoded from it and the text of the file
  are zeroed when the install ends, however it ends, and so are the text and the DER of a key file the agent reads. That is best
  effort: the gRPC library keeps its decode buffer, the PEM reader the base64 of the key in a buffer it grows and frees, and the TLS
  library its copy of the key.
- The agent reports each app whose bundle names an uploaded certificate in a `CertificateStatus`: `active` (the named certificate is
  served; `chain_pem` is the served chain written again from its DER, `leaf_sha256` its leaf), `missing` (it is not held; the
  certificate served meanwhile, if there is one, is described, and the control plane answers with the install) or `failed`. One goes
  out after each live bundle, applied or refused, on the first try and on every retry, and none after the cached bundle of a start;
  then one for each change of state or of the served leaf, and one each minute while the state is `missing`. An app sends at most
  one in ten seconds: a change inside that time goes out when it is over, as the latest state only. An app whose source is empty
  or not known, or that is uploaded with no certificate named, has none. An app with the source `acme` reports through its order, see
  below. A bundle that is refused because a `tls` object fails a check, or because an
  HTTPS or redirect address cannot be bound, gives each uploaded app in it `failed` with a fixed phrase: `the bundle was refused: its
  TLS settings are not valid`, or `cannot listen on 0.0.0.0:443: address in use` (the address and the kind of the error). For an
  address that cannot be bound `next_attempt_unix` is a minute ahead, when the bundle is tried again; for a refused `tls` object it is
  0, as a retry of the same bundle fails the same check. The refusal changes nothing in force, so an app whose bundle in force still names
  a certificate the agent does not hold asks for it again (`missing`) once its `failed` has gone, and then every minute. An app that
  is ordered a certificate gets no `failed` from a refused bundle: it reports through its order, so the status of such an app does not
  say that its bundle cannot bind. A bundle
  refused for any other reason (a plain app on the address of an HTTPS listener, say) says nothing of the certificates: each app
  reports the state it is in. An error text has its control characters
  removed, is cut to 1 KiB on a character boundary, and becomes `error text withheld` when it holds `-----BEGIN` or `PRIVATE KEY`.
- An app whose source is `acme` has its certificate ordered by the agent from the ACME directory it is configured with, for all its
  `hosts` in one order. Nothing is ordered until the bundle asks for it. The agent has one account for each directory: an ECDSA P-256 key
  with no contact address, the terms of service agreed to (the request button of the dashboard is the acceptance), in `acme-account.json` of
  the key directory, 0600, and made again when the directory is not the one the file names. It is in no log line, no status and not
  in `state.json`. One worker orders, in the process that holds the key directory lock, one order at a time, the app that has been
  due the longest first; the process that a reload replaces starts no new order once the successor is being started (the authority's check
  of a name may reach the successor, which has no answer for it), lets one that is running go on, and stops its worker when it lets the lock
  go, keeping an order that ends before that. The requests to the authority go through the agent's own HTTP client, so they use the platform's root certificates and `HTTPS_PROXY`
  like its other downloads, and only to https addresses: the directory is one, and so must be every address it names. An order is due when
  the app has no certificate of its own (`acme-<app id>.pem`), when a host of its entry is not among the names of that certificate, and when
  the entry has an `acme_request_id` that no order has answered, at once and also while the last order waits for its next try. An order that
  failed is tried again at its next try even when the app has a certificate of its own, as a new `acme_request_id` asked for another, unless
  that certificate covers every host the app has now and the failed order was for a host the app has dropped since: nothing is then
  asked for that the certificate does not give, and the app is `active`. An order has 3 minutes. The authority is not trusted with which names to prove: an order whose authorizations are more than its names, or
  for a name that is not one of them, fails before anything is answered. The agent answers the challenge of the authority with its own listeners: TLS-ALPN-01 on the HTTPS listener and HTTP-01 on the
  redirect listener and on the HTTPS listener, and takes the answers down however the order ends. It chooses the challenge that last worked,
  else TLS-ALPN-01 for a `listen` on port 443 and HTTP-01 for a `redirect_listen` on port 80, else TLS-ALPN-01; after a failed order it
  tries the other; a failure says when the app has no listener the challenge needs, and for HTTP-01 on an app with no
  `redirect_listen` on port 80 that adding one is the way out. A name the authority already holds a proof for gets no challenge. The key of a certificate is a new ECDSA P-256 key
  for every order, and the chain that comes back is checked as an uploaded one is, and must cover every host, before it is kept
  (`acme-<app id>.pem`, written as the other certificate files are) and served from the next handshake on. An order that finishes
  after its app left the bundle, left gateway mode, changed its source or its hosts is dropped and writes nothing; a new request id
  with the same hosts and source does not drop it. After a failed order the next one waits 10 minutes, with the other challenge, and
  a change to the hosts does not shorten that wait; a new request id does;
  `state.json` keeps the id the last order answered, the challenge that worked, the failures and the hosts of the failed order, the time
  of the next try and the text of the last error, so a restart does not order sooner.
- An ordered certificate reports `pending` (an order is running or due, also before the first one; `chain_pem` is the certificate in use
  meanwhile, if any), `active` (the ordered certificate is served and covers every host) or `failed` (the last order failed: `error` is a
  fixed phrase with the problem type and detail the authority gave or the kind of the I/O error, and `next_attempt_unix` the time of the
  next try). `request_id` is the id of the bundle entry the state answers: an order that ends under an id that is no longer the entry's
  reports nothing for the new one, which stays `pending` until its own order has run.
- Before its first certificate an ordered app is served a placeholder: a self-signed certificate for its hosts, made from one key for the
  process and never written to the key directory, and not made again by a bundle that leaves the hosts as they were. A browser warns instead of the handshake failing, and an authority that reaches the app
  through a CDN that sends port 80 to HTTPS can then get its answer. The app itself is not reached: such a connection gets `503` and the
  answers to a validation, and the redirect listener answers `503` too, not `308`. A client that clicked through the warning has a TLS
  session that a resumption can bring back without a new certificate, and a resumed placeholder session can reach the app. A bundle
  never gives such an app a plain listener, so a login or a cookie never goes over plain HTTP before the certificate is there.
- Ports 80 and 443 have to be open to everyone for an order: the authority validates from several networks, and a host firewall or an XDP
  allowlist that lets only some through makes the order fail. Behind a CDN the mode that connects to the origin over HTTPS ("Full")
  works with HTTP-01 and never with TLS-ALPN-01, which a CDN does not pass; the mode that connects over plain HTTP loops.
- Apps that give the same `listen` share the listener and may differ in their `proxy_config`; a host name belongs to one app on a
  listener. Before a request is routed its head is read with the largest read buffer and the largest finite read timeout of those apps, and an answer made
  then uses the largest finite write timeout (60 seconds when no app has one). From the routing on each app's own settings
  apply: a head longer than its read buffer gets `431`, its read timeout counts from the start of the head and covers the body,
  and its body limit and write timeout hold. An unlimited timeout applies after the routing only, so an idle connection on a
  listener where one app is unlimited still ends at the finite timeout of another. A change of these settings takes effect
  with the next bundle, without a restart. An address that changes from a plain listener to a redirect listener, or from HTTPS
  to a plain listener, keeps its socket: no connection is refused and new ones get the new kind. A request in flight on an old
  connection finishes; an old connection that is idle between requests closes at once.
- An app with a `tls` object opens no plain listener of its own: the address its bundle names is not served and not checked (another
  app may use it), and the app answers on its HTTPS listener only. An address of the object that another app of the bundle uses
  fails the apply with `duplicate listener in WAF bundle`.
- TLS 1.2 and 1.3. The SNI name picks the app and the certificate the agent holds for it, and the `Host` header picks the app.
  ALPN is `acme-tls/1`, then `http/1.1`: a client that offers `acme-tls/1` is a certificate validation, and gets a handshake only
  for a name with a validation pending, which ends with the handshake; every other client negotiates `http/1.1` or none. A client
  that sends no name, or a name no `hosts` list has, gets no handshake. A `Host` that differs from the SNI name gets `421`
  and the connection closes, so no request reaches another app's upstream over a certificate that was not made for it.
- A new certificate is served from the next handshake on, and open connections go on. A file that cannot be read, or whose key does
  not match its certificate, is not served: the app keeps the certificate it has, and the file name and the kind of failure are
  in the log. Private keys are never logged.
- `redirect_listen` answers every method with `308` to `https://<host>[:port]` and the same path and query, for the hosts of the app, and
  `404` for any other, then closes the connection. It answers `503` with `Retry-After: 60` instead of the `308` for an app that has
  no real certificate yet. A `GET /.well-known/acme-challenge/<token>` for a name with that HTTP-01 validation pending gets `200` and
  the key authorization, here and on the HTTPS listener, before the request is routed.
- The agent computes the JA4 fingerprint from the ClientHello of each TLS connection, and the bot checks use it. For an app
  with a `tls` object, the JA4 and JA3 headers of a proxy in front are read only from a peer that `proxy_config` trusts as a proxy; `X-Forwarded-Proto`
  is `https` for a TLS connection. A ClientHello that spans two TLS records gets no JA4.
- Every TLS connection counts against the listener's connection limit, and the handshake has 10 seconds. A failed handshake closes
  without an answer.

## Switching inspection off

`semantic_policies.inspection_off` switches inspection off for the project, and a path exception's `inspection_off` does it
for that path: the request is allowed after the checks that never depend on the engines (body size limit, path
block, rate limits, flood, geo, bot, custom rules), with the message `inspection off: project setting` or
`inspection off: path exception`. Documents of version 1 name the switch `disable_semantic` (together with
`disable_rule_based`); `inspection_off` and `disable_semantic` mean the same here, and `disable_rule_based` alone
means nothing. `skip_coraza_when_clean`, the category entries `RFI`, `Method`, `Generic`, `Scanner`, `Protocol`,
`Multipart` and `SessionFixation`, a tuning rule's `skip_crs` and the body buffer limits
(`request_body_in_memory_limit`, `response_body_limit`) of version 1 documents are read and ignored. A tuning
`scan_mode` is `default`, `both` or `disabled`; `crs_only` and `semantic_only` read as `default`.

## Detector switches

Every detector has a key that the control plane can switch off. The key is read in three places, with the same
shape in each: the project's `semantic_policies.<key>.disabled`, a path exception's
`semantic_override.<key>.disabled` (which also switches the key back on for that path), and the names in a tuning
effect's `skip_semantic` (`"*"` names every key). A key a rules document does not mention is on. A key this agent
does not know is ignored and logged when it sits in a path `semantic_override` or a path tuning `skip_semantic`, and
ignored silently in `semantic_policies`; it never makes the agent refuse the document.

| Key | Category it reports | Detectors under it |
|---|---|---|
| `sql` `xss` `cmd` `php` `python` `lfi` `ssrf` `java` | SQLi, XSS, RCE, PHP, Python, LFI, SSRF, Java | The engine of the same name, with the fast paths and the probes that report as that category: server-side include directives (`xss`, `cmd`), script and upload names, system file paths and `WEB-INF` (`lfi`), out-of-band hosts (`ssrf`), PHP open tags in uploads (`php`) |
| `nosql` `ssti` `xxe` `deser` `ldap` `proto_pollution` | NoSQLi, SSTI, XXE, Deserialization, LDAP, PrototypePollution | The engine of the same name; XML and XPath probes and schema locations are `xxe`, serialized objects are `deser` and `php` |
| `jwt` `graphql` | JWT, GraphQL | Header attacks on a JWT; introspection and the batch limit (`graphql`) |
| `header_injection` | HeaderInjection | A line break behind a header, mail or cache command, in a value, a header, the path (decoded, escaped or hidden under base64) |
| `open_redirect` | OpenRedirect | A redirect parameter that names another origin |
| `prompt_injection` | PromptInjection | Instructions aimed at a language model; a hit in the address of a chat path blocks |
| `anomaly` | Anomaly | The User-Agent of a scanner, control characters and entropy in a long value, a query parameter the project has not seen before |

Every key that is switched off for a request (by the project, by the path or by a tuning rule; `"*"` is all twenty)
is listed as `engine_disabled:<key>` in the `coverage` text of the decision event. The mark is informational. It is not
a coverage gap, never raises a clean allow to a log line, is not counted in the partial-coverage metric and is not part
of `match_detail`.
Request smuggling, the route's invalid percent-encoding check and the features with their own settings (bot, geo,
flood, content scanning, custom rules) have no key.

## Log-only engines

A key also takes `action`: `semantic_policies.<key>.action` for the project and `semantic_override.<key>.action` for
a path. `"block"` and an absent key block, as always. `"log"` keeps the detection and drops the block: what the key
would have blocked becomes a LOG decision with the category, match detail and match source of the block (and the score of a strong detection of that category), the
request goes on to the upstream, and the key is listed as `engine_log_only:<key>` in the `coverage` text of the event.
An override that sets no action inherits the project's; `disabled` wins over `log`. Any other value is dropped at
load and logged, and the key keeps the action it inherits (block when none is set). Every key accepts it; `open_redirect`, `prompt_injection` and `graphql`
introspection only log in the scan, so `log` changes nothing for those.

A request is held only when every engine that still blocks finds nothing: the scan runs again as if the log-only keys
were off, and a block of another key stands. The held decision is not a block for the block policy or the IP jail, and
monitor mode records it as `log`. The blocks that belong to a key follow it: a prompt injection in the address of a
chat path (`prompt_injection`), a GraphQL batch over the limit (`graphql`), the User-Agent of a scanner (`anomaly`), an
out-of-band host (`ssrf`) and a WebSocket frame that an engine blocks. A tuning `skip_semantic` applies first.
Request smuggling, the invalid percent-encoding check, body limits, rate limits, geo, bot, content scan,
custom rules and the uninspected-content floor stay as they are.

A tuning rule (a custom tuning rule, or the `tuning` of a path exception) with `effect.action: "log"` holds every key the same
way for the requests it matches: the strong detection becomes a LOG decision that lists the key as `engine_log_only:<key>`.
The `weaken` effect of earlier versions is read as that action when it lowered scores (`score_multiplier` above 0 and below 1) or
raised the block threshold (a positive `threshold_delta.block`); any other `weaken` is ignored. There is no coverage mark for
a weakened engine any more.

## Weak detections

A weak detection is a LOG decision and the request goes on. `semantic_policies.record_weak_detections` (absent means true)
set to false lets it through with no decision. A strong detection that a log-only engine holds back is still a LOG, whatever
this key says.

## Documents of version 1

A rules document of version 1 still loads, and what it said about scores reads as follows. `thresholds.block` and
`thresholds.log` are ignored, except that a document whose `log` is not below its `block` (an absent or zero value reads as
the default, 80 and 150) and that has no `record_weak_detections` reads as `record_weak_detections: false`. A
`base_score` is ignored, in `semantic_policies.<key>`, in a path `semantic_override.<key>` and in `categories.<name>`, except
that a `base_score` of 0 on an engine reads as that engine disabled (not on `header_injection`, `open_redirect`,
`prompt_injection` and `anomaly`, which only switch), and a category of 0 as disabled on the engines that
fall back to it (`sql`, `xss`, `cmd`, `php`, `python`, `lfi`, `ssrf`, `java`) and name no base score of their own. A path
`rule_override` is ignored. `bot_protection.score_threshold` (default 150) is what the bot score is compared with in Score
mode; it replaces the block threshold. The per-engine `block_threshold` and `soft_threshold` are evidence thresholds and stay.

## Request body decoding

The engines inspect a decoded copy of a request body; the application behind the agent gets the bytes the client sent.
`Content-Encoding` values `gzip`, `x-gzip`, `deflate` (zlib-wrapped or raw) and `br` are decoded, up to three stacked
codings. All of it is Rust: `miniz_oxide` inflates the deflate data, the `brotli` crate decodes brotli, and the gzip and
zlib framing (headers, member trailers, checksums) is checked in `crates/bodyinspect/src/decode.rs`. Any other coding
(`zstd`, `compress`, a name the agent does not know) is not decoded: the body is inspected as it arrived and the
decision carries `body_content_encoding:<name>`.

Limits: the decoded copy is at most 8 MiB or the route's body limit, whichever is smaller, and at most the larger of
256 KiB and 100 times the size on the wire; a body that would grow past that is cut there (`body_decompress_limit`). A
body that does not decode, including a gzip or zlib stream with a bad checksum or bytes after its end, is inspected as
received (`body_decompress_error`).
`WAFIO_BODY_DECODE_BUDGET_BYTES` (default 64 MiB, 0 disables) caps the memory of decodes in flight; a body that does not
fit is inspected as received (`body_decompress_budget`).

The only C code in the binary is the TLS provider (`ring`) and the allocator (`mimalloc`). `cargo tree` still lists
`zstd-sys` and `libz-ng-sys` under `pingora-core`; nothing calls them and the linker drops them. On a release binary,
`nm wafio-waf-agent-open | grep -E 'zng_|ZSTD_'` prints nothing.

## Protocol file

`proto/agent/v1/agent_control.proto` is a copy of wafio-cp-backend's `shared/proto/agent/v1/agent_control.proto`;
`proto/SOURCE` names the tag it was copied at and its sha256. `crates/proto/build.rs` compiles it with `protox` and
`tonic-prost-build`, so no `protoc` is needed. A protocol change starts in wafio-cp-backend; then run
`scripts/sync-proto.sh <tag>` here. `scripts/sync-proto.sh --check` is part of the gate.

`CertificateInstall` carries a private key, and prost ignores the proto's `debug_redact`. So `build.rs` leaves out the
derived `Debug` of that message and `crates/proto/src/lib.rs` writes one that prints the ids, the leaf digest and the
two byte lengths, which makes the `Debug` of `ServerMessage` safe too. The same file gives the message a `Drop` that
zeroes `key_pem`, so a key does not stay in freed memory however the message ends: installed, refused, drained from a
closing stream or dropped by a panic. This is best effort: tonic keeps its own decode buffer.

## Release

The release bundle is made by wafio-release `scripts/release.sh <version> --waf-agent <binary>`, which takes the
baseline binary and the notice files that `scripts/build-dist.sh --container` of wafio-semantic-engine writes into one directory;
the script checks the binary against `VERSION` and `SHA256SUMS` there and refuses the x86-64-v3 build, a binary that does not
carry the engine (the agent of this repository alone), and a binary that names a glibc above 2.28 (`WAFIO_MAX_GLIBC`). The bundle layout (`wafio-waf-agent`, `systemd/wafio-waf-agent.service`, installer,
notices) is defined in wafio-release `deploy/BUNDLE.md`. The gnu binary links the glibc of the build host, and the
highest `GLIBC_` version it names is the oldest glibc it starts on; the build prints that version and the bundle
installers refuse an older host.

Supported distributions are the ones the release binary was started on (container images, 2026-11-16): AlmaLinux 8.10,
Rocky Linux 8.9, Debian 11, Ubuntu 20.04, Rocky Linux 9.3, Ubuntu 22.04, Debian 12, Ubuntu 24.04 and Debian 13. Ubuntu
18.04 (glibc 2.27) and CentOS 7 (glibc 2.17) are refused. Others with glibc 2.28 or newer should work and have not been
started. Only the Ubuntu 24.04 build host ran the agent under systemd, as a transient user service; the other
distributions ran it in a container (`deploy/BUNDLE.md` has the table). A customer server that still runs version 1 has
the Go agent until it takes a release made this way.

## Layout

```
Cargo.toml  Cargo.lock       workspace of 18 crates
crates/
  waf-agent                  the library and the binary wafio-waf-agent-open: flags, run loop, bundle apply, key directory, uploaded and ordered certificates, reload
  control                    gRPC link to the control plane, bundle cache, telemetry
  proxy                      per-application reverse proxy and WebSocket handling, HTTPS listeners and certificates
  application                request analysis pipeline, in-memory block and rate-limit stores
  engine-api                 the engine boundary: scan configuration, finding names, coverage marks, the Engine trait
  engine-abi                 the C interface to an engine in a shared library: structs, symbols, header, encodings
  engine-loader              loads and checks the library and presents it as an Engine; the only crate with unsafe for it
  engine-fake                a fake engine for the tests of the other crates
  engine-rules               rules JSON, path exceptions, custom rules, bot checks, script rule budget
  agent-io, agent-pages      FastCGI, client IP trust, IP jail, WebSocket scan, challenge pages
  bodyinspect, domain, geo, lru, malware, bytetext   request bodies, shared types, GeoIP,
                             bounded LRU, malware hashes, byte-level text helpers (UTF-8, URL, HTML, patterns, transforms)
  proto                      generated gRPC client and server
proto/                       vendored protocol file and its SOURCE
scripts/                     ci-local.sh  build-dist.sh  gen-test-certs.sh  gen-notices.py  sync-proto.sh  check-ai.sh  advisories.py  pebble.sh
scripts/notices/             notices.json and the licence texts that gen-notices.py puts into NOTICES.txt
tools/core-gen               Go generators for the bytetext Unicode and HTML entity tables
```

## License

Copyright (C) 2026 Wafio. This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 only, as published by the Free Software Foundation. It comes without any warranty. The full text is in `LICENSE` (SPDX: `GPL-3.0-only`). The notices of third-party code, including code adapted from other projects, are in `NOTICES.txt`, which `scripts/gen-notices.py` generates and every bundle carries.
