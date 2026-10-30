# Sniffer di rete con raw socket (solo Linux)
# Eseguire con: sudo python3 sniffer.py

import socket
import struct


def mac_address(dati):
    return ':'.join('%02x' % b for b in dati)


def ip_address(dati):
    return '.'.join(str(b) for b in dati)


# creo il socket raw che riceve tutti i pacchetti (0x0003 = tutti i protocolli)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

print("Sniffer avviato, premi Ctrl+C per fermarlo\n")

numero = 0

try:
    while True:
        pacchetto, indirizzo = s.recvfrom(65535)
        numero += 1

        # header Ethernet (primi 14 byte)
        mac_dest, mac_sorg, tipo = struct.unpack('!6s6sH', pacchetto[:14])
        print("Pacchetto n.", numero)
        print("  MAC sorgente:", mac_address(mac_sorg), "-> MAC destinazione:", mac_address(mac_dest))

        # 0x0800 = IPv4, gli altri tipi li salto
        if tipo != 0x0800:
            print("  Non e' un pacchetto IPv4\n")
            continue

        # header IP (20 byte dopo l'Ethernet)
        ip_header = pacchetto[14:34]
        ip = struct.unpack('!BBHHHBBH4s4s', ip_header)

        lunghezza_header = (ip[0] & 15) * 4
        ttl = ip[5]
        protocollo = ip[6]
        ip_sorg = ip_address(ip[8])
        ip_dest = ip_address(ip[9])

        print("  IP sorgente:", ip_sorg, "-> IP destinazione:", ip_dest, " TTL:", ttl)

        inizio = 14 + lunghezza_header

        # protocollo 6 = TCP
        if protocollo == 6:
            tcp = struct.unpack('!HHLL', pacchetto[inizio:inizio + 12])
            print("  TCP  porta", tcp[0], "->", tcp[1])

        # protocollo 17 = UDP
        elif protocollo == 17:
            udp = struct.unpack('!HHHH', pacchetto[inizio:inizio + 8])
            print("  UDP  porta", udp[0], "->", udp[1])

        # protocollo 1 = ICMP
        elif protocollo == 1:
            icmp = struct.unpack('!BBH', pacchetto[inizio:inizio + 4])
            print("  ICMP tipo", icmp[0], "codice", icmp[1])

        else:
            print("  Altro protocollo:", protocollo)

        print()

except KeyboardInterrupt:
    print("\nSniffer fermato. Pacchetti catturati:", numero)
    s.close()
