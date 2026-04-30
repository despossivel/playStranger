# Xbox One UPnP Unauthorized Media Redirection (CWE-306 + SSRF)

## Summary
The UPnP AVTransport control endpoint exposed by `udhisapi.dll` on Xbox One accepts critical SOAP media-control actions from any host on the local network without authentication, pairing, PIN, or authorization checks.

By calling `SetAVTransportURI` and then `Play`, an attacker can force the console to request attacker-controlled URLs. This behavior enables unauthorized media redirection and a practical SSRF primitive from an adjacent network position.

## Vulnerable Action
- `urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI`

## Root Cause
Missing authentication and authorization for critical control functions in the UPnP AVTransport service.

## Weakness Classification
- Primary: CWE-306 (Missing Authentication for Critical Function)
- Secondary: CWE-918 (Server-Side Request Forgery)
- Potential impact extension: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

## Affected Component
- Endpoint pattern: `/upnphost/udhisapi.dll?control=...+urn:upnp-org:serviceId:AVTransport`
- Service: UPnP AVTransport (IIS UPnP host stack)

## Attack Prerequisites
- Attacker is on the same L2/L3 local network segment (or can route to TCP/2869 on target)
- Target UPnP host service reachable
- No prior authentication required

## Proof of Concept Behavior
1. Send SOAP `SetAVTransportURI` to point the target to attacker URL.
2. Send SOAP `Play`.
3. Target performs outbound HTTP GET to attacker server.
4. Attacker observes request metadata (`User-Agent`, `Range`, DLNA headers, and other request context).

## Security Impact
- Unauthorized remote control of media transport state
- SSRF primitive from console to attacker-controlled endpoint
- Information disclosure via unsolicited request headers and device fingerprinting
- Potential chained risk if downstream parser bugs exist in media stacks

## Severity Notes
If no single CVE maps to the exact Xbox firmware build under test, document this as:
- "Zero-Day Logic Flaw"
- "UPnP Unauthorized Media Redirection"

Suggested preliminary CVSS v3.1 (to be validated by triage):
- `AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`

Rationale:
- Adjacent network attack vector
- No privileges or user interaction needed
- Confidentiality and integrity are impacted at low level in baseline case

## Reproduction Evidence Checklist
- SOAP request and response for `SetAVTransportURI`
- SOAP request and response for `Play`
- Packet capture showing outbound request from target
- HTTP server logs showing request path and headers
- Firmware/build identifiers if available

## Recommended Remediation
- Enforce authentication and authorization before accepting AVTransport actions
- Restrict control endpoint exposure to trusted paired clients only
- Require explicit user consent or pairing flow for remote transport control
- Add allowlist validation for remote media URIs and block private/unsafe destinations when appropriate
- Add telemetry and rate-limits for repeated control actions

## Disclosure Label (if CVE unavailable)
"UPnP AVTransport Missing Authentication leading to Unauthorized Media Redirection (SSRF-capable)"
