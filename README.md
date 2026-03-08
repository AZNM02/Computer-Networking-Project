# Computer Networking Project

A series of three networking labs built in Python 3, covering low-level socket programming, software-defined networking (SDN), and HTTP proxy design.

---

## Lab 1 — Custom Binary Protocol over UDP and TCP

A from-scratch implementation of a multi-stage client-server handshake protocol using raw BSD sockets. Both a client (`lab1/part1/`) and a fully functional server (`lab1/part2/`) were implemented.

### Protocol Design

Every message — sent over either UDP or TCP — is framed with a 12-byte big-endian binary header:

| Field | Size | Description |
|---|---|---|
| `payload_len` | 4 bytes | Length of the payload in bytes |
| `psecret` | 4 bytes | Previous stage's secret (used for authentication) |
| `step` | 2 bytes | Protocol step number |
| `student_id` | 2 bytes | Last 3 digits of student ID |

Payloads are padded to 4-byte alignment. Headers are packed and unpacked using Python's `struct` module with the `!` (network/big-endian) byte-order specifier.

### Handshake Stages

**Stage A (UDP — Discovery)**
The client sends a `"hello world\0"` datagram to a known port. The server responds with four parameters: `num`, `length`, `udp_port`, and `secretA`. All subsequent communication is authenticated against the secrets received in prior stages.

**Stage B (UDP — Reliable Bulk Transfer)**
The client sends `num` numbered UDP packets (each containing a 4-byte packet ID followed by `length` zero bytes) to the new `udp_port`. The server randomly drops ACKs to simulate an unreliable network; the client retransmits on timeout and strictly enforces in-order delivery. Once all packets are acknowledged, the server sends a new `tcp_port` and `secretB`.

**Stage C/D (TCP — Authenticated Data Exchange)**
The client opens a TCP connection and receives `num2`, `len2`, `secretC`, and a single ASCII character `c`. It then sends `num2` TCP payloads each consisting of `len2` repetitions of `c`. The server validates every byte and responds with the final `secretD`.

### Key Technologies
- Python `socket` (UDP `SOCK_DGRAM` and TCP `SOCK_STREAM`)
- Python `struct` for binary serialisation with big-endian byte order
- `threading` — the server spawns a daemon thread per client session
- Manual retransmission loop with `socket.timeout` for UDP reliability
- `recv_exact()` helper to guarantee full-message reads over TCP streams

---

## Lab 2 — Software-Defined Networking with Mininet and POX

Four progressively more complex network topologies and SDN controllers, built using the **Mininet** network emulator and the **POX** OpenFlow controller framework.

### Part 1 — Basic Topology
A single OpenFlow switch (`s1`) connecting four hosts (`h1`–`h4`). Used to explore Mininet's Python API: `addSwitch`, `addHost`, `addLink`, and the interactive `CLI`.

### Part 2 — Stateless Firewall
Same single-switch topology, but now controlled by a POX `Firewall` component. OpenFlow flow rules are installed at startup to enforce a simple policy:
- **Allow** all ARP traffic (`EtherType 0x0806`) — flood to all ports
- **Allow** all ICMP traffic (`IP + nw_proto=1`) — flood to all ports
- **Drop** all other IPv4 traffic by default (no-action flow entry at lower priority)

### Part 3 — Multi-Switch Routing with Access Control
A two-tier topology: three edge switches (`s1`, `s2`, `s3`) feed into a core router switch (`cores21`), which connects to a data-centre switch (`dcs31`) hosting a server. An untrusted external host (`hnotrust1`, subnet `172.16.10.0/24`) is also attached to the core.

The `Part3Controller` installs **static OpenFlow rules** per switch at connect time:
- Edge switches flood all ARP and IPv4 traffic.
- `cores21` implements **destination-based routing**: a dedicated rule per host IP forwards packets out the correct port toward that host.
- **Firewall rules** (higher priority, no actions = drop):
  - Block all IPv4 from `hnotrust1` → `serv1`
  - Block all ICMP from `hnotrust1` → any internal host (`h10`, `h20`, `h30`, `serv1`)

### Part 4 — Reactive Learning Router with ARP Proxy
Same topology as Part 3, but the `cores21` controller now behaves as a **reactive, self-learning IP router**:
- Firewall drop rules are pre-installed identically to Part 3.
- The controller **learns host locations dynamically**: when an ARP packet arrives, the sender's IP, MAC, and ingress port are recorded in an in-memory table.
- Once a host is learned, a **per-destination flow rule** is installed that rewrites both source and destination MAC addresses (using the router's per-port MAC) and forwards out the correct port — eliminating flooding for known destinations.
- The controller responds to **ARP requests for gateway IPs** (e.g., `10.0.1.1`) by synthesising ARP replies using the appropriate router MAC, enabling hosts to use default-route-style forwarding without requiring ARP flooding to the controller.

### Key Technologies
- **Mininet** — virtualised network topology with Linux network namespaces
- **POX** — Python-based OpenFlow 1.0 SDN controller
- **OpenFlow 1.0** (`pox.openflow.libopenflow_01`) — `ofp_flow_mod`, `ofp_action_output`, `ofp_action_dl_addr`
- `pox.lib.addresses` — typed `IPAddr` and `EthAddr` wrappers
- `pox.lib.packet` — parsed Ethernet, ARP, and IP packet objects

---

## Lab 3 — Multithreaded HTTP/HTTPS Proxy

A concurrent forward proxy server (`lab3/proxy.py`) that sits between a browser and the internet, forwarding HTTP requests and tunnelling HTTPS connections.

### Architecture

The proxy listens on a configurable TCP port. Each incoming client connection is dispatched to a new thread, allowing many clients to be served simultaneously without blocking.

### HTTP Handling
1. The proxy reads the client's request headers using a robust `recv_until_header_end()` reader that handles both `CRLF` and `LF` line endings.
2. The request is rewritten by `rewrite_request_header()`:
   - Downgrades the HTTP version to `HTTP/1.0` to ensure the server closes the connection after the response.
   - Removes or replaces `Connection` and `Proxy-Connection` headers to prevent keep-alive mismatches.
   - Extracts the target `host` and `port` from the `Host` header or the request URI.
3. The proxy opens a fresh TCP connection to the origin server, forwards the modified request, and streams the response back to the client. Response headers are similarly rewritten by `rewrite_response_header()`.

### HTTPS Tunnelling (CONNECT)
When the client issues a `CONNECT host:port` request (used by browsers for HTTPS), the proxy:
1. Opens a raw TCP connection to the destination.
2. Sends `HTTP/1.0 200 Connection Established` to the client.
3. Enters a `tunnel()` loop that uses `select()` to bi-directionally relay raw bytes between the client and the server — allowing TLS to be negotiated end-to-end without the proxy decrypting it.

### Key Technologies
- Python `socket` — TCP server socket with `SO_REUSEADDR`, per-connection sockets to origin
- `threading.Thread` — one daemon thread per client connection
- `select.select()` — I/O multiplexing for the bi-directional HTTPS tunnel
- HTTP/1.0 and HTTP/1.1 header parsing and rewriting
- Tested against real-world sites: Amazon, CNN, Google, YouTube, and others (captured outputs in `lab3/`)

### Running the Proxy
```bash
cd lab3
./run <port>          # e.g. ./run 1234
```
Then configure Firefox (or any browser) to use `localhost:<port>` as its HTTP and HTTPS proxy.
