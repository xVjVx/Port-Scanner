import sys
from scapy.all import * 

if len(sys.argv) != 4:
    print("[!] Correct execution: python3 %s [target] [startport] [endport]"%(sys.argv[0]))
    sys.exit(0)

target = str(sys.argv[1])
startPort = int(sys.argv[2])
endPort = int(sys.argv[3])
print("[!] Scanning "+target+" for TCP ports")

if startPort == endPort:
    endPort += 1

for i in range(startPort,endPort):
    try:
        packet = IP(dst=target)/TCP(dport=i,flags='S')
        response = sr1(packet,timeout=0.5,verbose=0)
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print("[+] Port "+str(i)+" is open")
        sr(IP(dst=target)/TCP(dport=response.sport,flags='R'),timeout=0.5,verbose=0)
        print("[!] Scan is complete\n")
    except:
        AttributeError
        print("[!] The target has no open doors\n")
        break