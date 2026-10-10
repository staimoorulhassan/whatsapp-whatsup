# Forensic Analysis: Exploitation of WhatsApp P2P Call Initiation ("Ringing" Phase) for Remote IP Address Discovery

---

## Executive Summary

WhatsApp is the world’s most widely used instant messaging and Voice over IP (VoIP) platform, serving over two billion active users. While end-to-end encryption (E2EE) using the Signal Protocol shields content payloads from interception, network routing requires data packets to reach physical network adapters via Internet Protocol (IP) addresses.

By default, WhatsApp voice and video calls utilize a **Peer-to-Peer (P2P)** mesh topology to minimize media latency and server overhead. A critical privacy side-effect of this architecture is that **a target’s public IP address can be harvested during the call initiation ("ringing") phase—without the recipient ever answering or accepting the call.**

This report presents a forensic investigation into the interactive connectivity establishment (ICE) protocols, STUN candidate exchanges, packet inspection methodologies, and security trade-offs governing WhatsApp P2P call setups.

---

## 1. Architectural Foundations: WebRTC, STUN, & ICE

To understand how IP address discovery occurs prior to call pick-up, it is necessary to examine the core network protocol suite utilized by WhatsApp for real-time media communications: **WebRTC (Web Real-Time Communication)**.

```
+-----------------------------------------------------------------------+
|                           WhatsApp Server                             |
|                       (XMPP / Noise Signaling)                        |
+----------------------------------+------------------------------------+
                                   |
                1. Call Signal     |  2. ICE Candidate Exchange
                & SDP Candidates   |     (Server-Relayed)
                                   v
+-----------------------+                    +--------------------------+
|  Caller (Attacker)    |                    |   Target (Victim)        |
|  Wireshark Listening  |<------------------>|   Phone RINGING          |
+-----------------------+  3. Direct UDP     +--------------------------+
                              STUN Probes
                         (PEER IP LEAKED HERE)
```

### 1.1 Signaling vs. Transport Path
WhatsApp decouples communication into two primary channels:
1. **Signaling Channel (Client-to-Server):** Operates over encrypted TCP sockets (typically port `5222` or fallback port `443`) using Meta’s customized Noise Protocol Framework. This handles authentication, user presence, call notifications, and cryptographic key exchanges.
2. **Media Transport Channel (Peer-to-Peer or Relayed):** Operates primarily over dynamic UDP ports using **SRTP (Secure Real-time Transport Protocol)** for encrypted audio/video payloads, and **STUN/ICE** for network path discovery.

### 1.2 STUN (Session Traversal Utilities for NAT - RFC 5389)
Because modern smartphones operate behind Network Address Translation (NAT) gateways, Carrier-Grade NAT (CGNAT), and stateful firewalls, a device does not inherently know its own public-facing IP address or external UDP port mapping. 

To resolve this, devices send a `STUN Binding Request` to a public STUN server. The STUN server inspects the incoming UDP packet header and returns a `STUN Binding Response` containing the `XOR-MAPPED-ADDRESS` attribute—the public IPv4 or IPv6 address and port allocated by the NAT router.

### 1.3 ICE Candidate Harvesting (Interactive Connectivity Establishment - RFC 8445)
When a call is initiated, the WebRTC engine on each device performs **candidate harvesting** to collect all potential network paths:
* **Host Candidates:** Local network interface addresses (e.g., Wi-Fi `192.168.1.45` or cellular internal IP `10.x.x.x`).
* **Server Reflexive (Srflx) Candidates:** The public IP and NAT-mapped port returned by STUN servers (e.g., `203.0.113.88:45120`).
* **Relay Candidates (Relay):** Server relay addresses allocated on TURN servers (e.g., `31.13.88.35:3478`).

---

## 2. Step-by-Step Mechanics of the "Ringing" Leak

The key factor enabling IP discovery is that **candidate harvesting and direct peer-to-peer connectivity probes occur concurrently with the alert/ringing notification**, long before the recipient interacts with the call UI.

### Phase 1: Call Trigger & Signaling Dispatch
1. **Caller A** clicks "Call" on **Target B**'s contact profile.
2. **Caller A's** device generates a call offer payload containing cryptographic parameters and its own harvested ICE candidates.
3. This offer is transmitted via WhatsApp's encrypted signaling server (TCP/5222) to **Target B**.

### Phase 2: Push Notification & Target Wake-Up
1. WhatsApp servers dispatch an APNs (Apple Push Notification service) or FCM (Firebase Cloud Messaging) alert to **Target B's** device.
2. **Target B's** WhatsApp application wakes up in the background and sets its status to **Ringing**.
3. Simultaneously, **Target B's** WebRTC stack automatically initializes and executes STUN candidate harvesting via Meta STUN infrastructure (e.g., `stun.whatsapp.net` or `157.240.x.x`).

### Phase 3: ICE Candidate Exchange via Server
1. **Target B** sends its candidate list—including its **Server Reflexive Candidate (Public IP)**—back through the encrypted signaling socket to the WhatsApp server.
2. The server forwards **Target B's** ICE candidates to **Caller A**.

### Phase 4: Direct P2P Connectivity Checks (The Leak Point)
1. As soon as **Caller A's** application receives **Target B's** candidate list, the ICE agent on **Caller A's** device begins sending **STUN Binding Requests** directly over UDP to all candidate IP addresses provided by **Target B**.
2. **Target B's** router/NAT receives these UDP STUN requests and replies with `STUN Binding Responses` to confirm path viability.
3. **Outcome:** A direct UDP network socket is established between **Caller A** and **Target B** while **Target B's** phone display is actively showing the incoming call screen (Ringing).

```
CALL LIFECYCLE TIMELINE:
[Call Clicked] ---> [Signaling] ---> [Push Sent] ---> [Target Rings] ---> [ICE STUN Probes Sent] ---> [Direct UDP Established] ---> [User Answers / Rejects]
                                                     |--------------------- IP EXPOSED HERE -----------------------|
```

---

## 3. Forensic IP Extraction Methodology (Wireshark Laboratory)

An analyst or adversary can capture and extract the remote peer's IP address using standard packet analysis tools.

### 3.1 Pre-Requisites & Environment Setup
* **Caller Device:** A mobile phone running WhatsApp connected to a network monitored by a packet capture interface (e.g., via a Linux Wi-Fi Access Point, Android `adb` packet capture, or a mirrored switch port).
* **Capture Tool:** Wireshark or `tcpdump`.
* **Target:** Any valid WhatsApp account (phone number).

### 3.2 Wireshark Capture Execution
1. Launch Wireshark on the monitoring interface.
2. Apply a capture filter restricted to UDP traffic or STUN protocols:
   ```bash
   udp
   ```
3. Place a WhatsApp audio or video call to the target.
4. Observe the packet stream as the target device begins to ring.
5. Immediately cancel the call after 2–3 seconds (before the target answers or declines).

### 3.3 Wireshark Display Filter Strategy
To isolate the target’s public IP from surrounding background noise, apply the following display filter string:

```wireshark
stun || (udp.port >= 3478 && udp.port <= 60000)
```

To filter out the caller's local IP and known local gateway:

```wireshark
ip.src == <CALLER_LOCAL_IP> && udp && !ip.dst == <LOCAL_GATEWAY_IP>
```

### 3.4 Packet Header & Attribute Breakdown

In the captured trace, locate the first non-Meta IP destination receiving UDP packets. The packet structure reveals the STUN candidate interaction:

```
Frame 142: 106 bytes on wire (848 bits), 106 bytes captured
Ethernet II, Src: Apple_xx:xx:xx, Dst: Router_yy:yy:yy
Internet Protocol Version 4, Src: 192.168.1.105 (Caller), Dst: 198.51.100.42 (Target Public IP)
User Datagram Protocol, Src Port: 54102, Dst Port: 3478
Session Traversal Utilities for NAT (STUN)
    Message Type: 0x0001 (Binding Request)
    Message Length: 44
    Message Cookie: 2112a442
    Message Transaction ID: 7f83a912b00421e4910a8e1b
    Attributes
        USERNAME: 4a21b9a0...
        PRIORITY: 1853818623
        SOFTWARE: WhatsApp WebRTC
```

* **Destination IP (`Dst: 198.51.100.42`):** Represents the target's public IPv4 address assigned by their ISP or cellular carrier.
* **Destination Port (`3478` or dynamic high port):** Represents the open UDP port mapped by the target's NAT router during candidate harvesting.

---

## 4. Technical Countermeasures & Defensive Analysis

Recognizing the privacy implications of P2P IP leaks, Meta implemented architectural toggles and platform defenses.

### 4.1 "Protect IP Address in Calls" Feature
WhatsApp introduced an opt-in security setting designed specifically to mitigate this vulnerability:
* **Path:** `Settings` -> `Privacy` -> `Advanced` -> `Protect IP address in calls`.

```
           DEFAULT P2P MODE                        PROTECTED TURN MODE
   +--------------+    +--------------+    +--------------+    +--------------+
   |   Caller     |    |   Target     |    |   Caller     |    | Meta TURN    |    |   Target     |
   | 203.0.113.15 |<-->| 198.51.100.42|    | 203.0.113.15 |<-->| Relay Server |<-->| 198.51.100.42|
   +--------------+    +--------------+    +--------------+    +--------------+    +--------------+
     Direct P2P Media / Probe Flow           Peer IPs Hidden behind Meta Infrastructure
```

#### Technical Effect of Activation:
1. **Suppression of Host/Srflx Candidates:** The target device's WebRTC engine is instructed to exclude local and server-reflexive candidates during harvesting.
2. **Forced TURN Relay Allocation:** The target advertises *only* Meta TURN server relay IP addresses (e.g., Meta Autonomous System `ASN 32934` ranges like `31.13.x.x` or `157.240.x.x`).
3. **Forensic Result:** Packet captures during ringing reveal only the IP addresses of Meta’s data centers. The target’s actual public IP remains completely hidden.

### 4.2 Comparative Security & Performance Matrix

| Feature Parameter | Default P2P Calling | Protected Relay Calling | Messaging (Text/Media) |
| :--- | :--- | :--- | :--- |
| **Network Architecture** | Peer-to-Peer (STUN) | Relayed (TURN) | Client-Server (Noise/TCP) |
| **IP Exposed During Ringing?** | **YES (Public IP Leaked)** | **NO (Meta Relay IP Only)** | **NO (Fully Opaque)** |
| **IP Exposed After Answering?**| **YES** | **NO** | **NO** |
| **Media Encryption Standard** | SRTP (AES-GCM) | SRTP (AES-GCM) | Signal E2EE Payload |
| **Latency / Audio Quality** | Optimal (Lowest RTT) | Marginally Higher RTT | N/A |
| **Server Bandwidth Overhead** | Low (P2P Hand-off) | High (Relay Traffic) | Low |

---

## 5. Scope & Limitations of Leaked IP Data

Understanding what an exposed IP address reveals—and what it does **not** reveal—is critical for threat modeling.

### 5.1 Intelligence Yielded by an Exposed IP
* **Coarse Geolocation:** Maps the target to a country, region, city, or postal code area via IP intelligence databases (MaxMind, DB-IP).
* **Internet Service Provider (ISP) / Mobile Network Operator (MNO):** Identifies whether the target is on home broadband (e.g., Comcast, BT, Vodafone) or a mobile network (e.g., T-Mobile, Verizon).
* **Network Infrastructure Type:** Discloses active VPNs, corporate proxies, or public Wi-Fi hotspots.

### 5.2 Technical Limitations & Protections
* **No Exact Physical Location:** IP addresses do not disclose physical street addresses or GPS coordinates.
* **Carrier-Grade NAT (CGNAT) Blurring:** On mobile 4G/5G networks, thousands of cellular devices frequently share a single public gateway IP address, making individual device isolation impossible from the IP alone.
* **Content Secrecy Unaffected:** IP address exposure does **not** compromise End-to-End Encryption (E2EE). Audio/video streams remain encrypted via SRTP keys exchanged out-of-band; packet interception yields unreadable ciphertext.

---

## 6. Summary & Recommendations

### Summary
WhatsApp’s default VoIP architecture prioritizes real-time audio quality and low packet latency by using WebRTC P2P direct connections. Because ICE candidate probing occurs immediately upon receiving a call offer, **a target user's public IP address is exposed to the caller during the ringing phase**, requiring no user interaction or acceptance of the call.

### Recommended Actions for High-Risk Individuals
1. **Enable IP Protection:** Enable `Protect IP address in calls` under WhatsApp Advanced Privacy Settings.
2. **Utilize a Network-Level VPN:** Route all device traffic through a trusted VPN endpoint to mask the underlying ISP/CGNAT IP address during STUN harvesting.
3. **Silence Unknown Callers:** Enable `Silence Unknown Callers` (`Settings` -> `Privacy` -> `Calls`) to prevent un-categorized phone numbers from automatically triggering the WebRTC wake-up and ringing state on target devices.