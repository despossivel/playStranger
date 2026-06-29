#!/usr/bin/env python3
import socket

msg = 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:3\r\nMAN:"ssdp:discover"\r\n\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg.encode(), ('239.255.255.250', 1900))
s.settimeout(3)

discovered = {}

try:
    while True:
        data, addr = s.recvfrom(1024)
        device_ip = addr[0]
        
        # REMOVIDA: Filtragem de IP específico
        # Agora captura TODOS os dispositivos
        
        if device_ip not in discovered:
            response = data.decode()
            discovered[device_ip] = True
            
            print(f"\n[+] Device: {device_ip}")
            for line in response.split('\r\n'):
                if 'USN' in line or 'Location' in line or 'location' in line:
                    print(f"    {line}")
except: 
    pass

s.close()
print(f"\n[*] Total devices discovered: {len(discovered)}")