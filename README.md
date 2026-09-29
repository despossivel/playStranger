# Playstranger

Playstranger is a lab repository for documenting an unauthenticated UPnP media-control exposure observed on Xbox One and Xbox Series. The material in this repository is organized for evidence preservation, responsible disclosure, and reproducibility in a controlled environment.

## Executive Summary

The target exposes the UPnP service surface through `udhisapi.dll` on TCP port 2869. In lab testing, multiple media-control and information-retrieval actions were reachable without pairing, PIN validation, or equivalent authorization checks. The captured evidence supports three impact classes:

- App Escape: remote media actions can interrupt foreground user activity by invoking media-handling flows.
- Hardware Control: rendering-related state changes are reachable from the local network.
- Information Disclosure: the service discloses device identity, protocol capabilities, current media state, and a large DLNA sink list without authentication.

## Attack Surface

The exposed surface is the Microsoft UPnP device host served by `udhisapi.dll`. The repository includes evidence for these service groups:

- `AVTransport:1`
- `RenderingControl:1`
- `ConnectionManager:1`
- DIAL descriptor exposure through the same host stack

Primary discovery and fingerprinting artifacts are preserved in the root capture files and summarized in the `evidence/` directory.

## Impact

### App Escape

Lab notes indicate that remote media redirection is capable of waking or foregrounding media-handling application flows, including Xbox video and music targets exposed through PlayTo capability strings.

### Hardware Control

The `RenderingControl` surface accepted control-oriented requests in lab testing, indicating that device output state can be influenced from the adjacent network.

### Information Disclosure

The target disclosed:

- device identity and model metadata
- service endpoints and UUIDs
- current connection identifiers
- current transport state indicators
- an extensive codec and protocol capability list
- PlayTo application targets for audio and video handlers

## Repository Layout

- `evidence/`: normalized markdown summaries of captured XML responses and discovery artifacts
- `notes/`: analyst observations distilled from the lab notebook
- `exploits/`: inventory placeholder for controlled-lab tooling references, intentionally kept non-operational in this repository

## Reproduction Overview

Use an isolated lab and only test against systems you own or are explicitly authorized to assess.

1. Discover the target through SSDP and record descriptor URLs.
2. Retrieve the MediaRenderer and DIAL descriptors to identify exposed services and UUIDs.
3. Query `ConnectionManager` and `AVTransport` read-oriented actions to confirm unauthenticated disclosure.
4. Validate control impact in a controlled session and capture the corresponding SOAP responses.
5. Preserve all SOAP responses, SSDP responses, and any outbound callback evidence for disclosure.

## Evidence Inventory

- Raw MediaRenderer descriptor: `1.xml`
- Raw DIAL descriptor: `2.xml`
- Raw current connection response: `GetCurrentConnectionIDs.xml`
- Raw protocol capability response: `GetProtocolInfo.xml`
- Raw current position response: `getPositionInfoResponse.xml`
- SSDP discovery capture: `logs.txt`

## Disclosure Position

At the time of this lab organization, the issue is tracked internally as:

- **PlayStranger**
- **Logical Vulnerability: Unauthenticated Authorization Bypass in Xbox One/Series UPnP Stack**
- **Primary class:** CWE-306 (Missing Authentication)

Technical distinction used for MSRC reporting:

- **Different impact:** this case is not limited to callback SSRF/exfiltration; it enables active UI/foreground interruption via `SetAVTransportURI` + `Play`
- **Observed effect:** App Escape and user-session interruption in a closed console environment

If no product-specific CVE is assigned, the repository position remains a product-context 0-day logical bypass under the PlayStranger designation.
