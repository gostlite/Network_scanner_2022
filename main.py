import scapy.all as scapy
import optparse

def get_args():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--ip', dest='ip_address', help='input your ip address')
    options = parser.parse_args()[0]
    if not options.ip_address:
        parser.error('input an ip address range')
    else:
        return options.ip_address


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    print(arp_request_broadcast.summary())
    answered = scapy.srp(arp_request_broadcast, timeout=2)[0]
    target_list = []
    for elem in answered:
        client_list = {"ip": elem[1].psrc, "mac_add": elem[1].hwsrc}
        target_list.append(client_list)
    return target_list

def get_addres(client):
    print("ip_address" +"\t\t\t\t\t" + "mac_address" +"\n"
          "-------------------------------------------------")
    for add in client:
        print(add["ip"] + "\t\t\t\t" + add["mac_add"])

ip = get_args()
client_add = scan(ip)
get_addres(client_add)