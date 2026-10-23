from scapy.all import sniff, IP, TCP, UDP, ICMP ,Raw

def analyze_packet(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol= "TCP"
        elif UDP in packet:
            protocol ="UDP"
        elif ICMP in packet :
            protocol = "ICMP"
        else :
            protocol ="other"

        print("Source IP:", source_ip)
        print("Destination IP:", destination_ip)
        print("Protocol :", protocol)

        if Raw in packet :
            payload = packet[Raw].load

            try:
                decoded_payload = payload.decode("utf-8")
                print("Decoded payload:", decoded_payload)

            except UnicodeDecodeError:
                print("Payload is not valid UTF-8 text")
                
            print("payload", payload[:50])
        else:
            print("Payload :no raw data available")

    print("-"*40)
print("Starting packet capture...")
sniff(prn=analyze_packet, count=10)