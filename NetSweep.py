import netifaces, ipaddress, subprocess, sys, os, prettytable, re, requests, time, multiprocessing, argparse, random
import concurrent.futures
import scapy.all as scapy

class Loader():
    def __init__(self, text, sign="."):
        self.text = text
        self.sign = sign

    def start(self):
        self.process = multiprocessing.Process(target=self.load, daemon=False)
        print(self.process)
        self.process.start()
        
    def load(self):
        dots = ""
        while True: 
            os.system("clear")
            print(f"{self.text}{dots}")
            if(len(dots) == 3):
                dots = ""
            else:
                dots += self.sign
            time.sleep(.5)

    def stop(self):
        self.process.terminate()
        os.system("clear")

def choose_interface() -> str:
    if_list = netifaces.interfaces()
    for interface in if_list:
        print("[{}] {}".format(if_list.index(interface)+1, interface))
    if_choice = int(input("\nChoose an interface: "))-1
    return if_list[if_choice]

def calc_network_addr(ip_addr, net_mask) -> str:
    network_addr = []
    ip_addr = ip_addr.split(".")
    net_mask = net_mask.split(".")
    for i in range(4):
        diff = int(ip_addr[i]) & int(net_mask[i])
        network_addr.append(str(diff))
    return ".".join(network_addr)

def get_ip_range(network: ipaddress.IPv4Network, my_ip: str) -> list:
    ip_range = []
    for ip in network.hosts():
        if(str(ip) == my_ip):
            continue
        ip_range.append(str(ip))
    return ip_range

def ping(ip: str)-> bool:
    parameter = 'n' if sys.platform =='win32' else 'c'
    try:
        subprocess.check_output(f"ping -{parameter} 1 {ip}", shell=True)
    except Exception:
        return False, ip
    return True, ip

def ping_sweep(ip_list: list)->list:
    reached = []
    futures = []
    with concurrent.futures.ThreadPoolExecutor(len(ip_list)) as executor:
        for ip in ip_list:
            future = executor.submit(ping, ip)
            futures.append(future)
    for future in futures:
        if(future.result()[0]):
            reached.append(future.result()[1])
    return reached

def get_mac_address(ip_list: list)-> list:
    ip_mac_list = []
    mac_search = re.compile('(\w{2}:){5}\w{2}')
    for ip in ip_list:
        res = str(subprocess.check_output(f"arp -n {ip}", shell=True))
        mac_addr = mac_search.search(res).group(0)
        line = [ip, mac_addr]
        ip_mac_list.append(line)
    return ip_mac_list

def get_vendor(ip_mac_list: list)-> list:
    final = []
    for ip_mac in ip_mac_list:
        line = [ip_mac[0], ip_mac[1]]
        url = f"https://api.macvendors.com/{ip_mac[1]}"
        r = requests.get(url)
        if(r.status_code == 200):
            line.append(r.text)
        final.append(line)
        time.sleep(1)
    return final

def pretty_print(ip_mac_vendor: list, args)-> None:
    table = prettytable.PrettyTable()
    if(args.tcp is not None):
        table.field_names = ["Actives IP", "Mac Address", "Vendor", "Open Ports"]
        for line in ip_mac_vendor:
            try:
                ports = ",".join(str(port) for port in line[3]) if line[3] != "No open ports" else line[3]
                table.add_row([line[0], line[1], line[2], ports])
            except IndexError:
                ports = ",".join(str(port) for port in line[2]) if line[2] != "No open ports" else line[2]
                table.add_row([line[0], line[1], "No vendor found", ports])
    else:
        table.field_names = ["Actives IP", "Mac Address", "Vendor"]
        for line in ip_mac_vendor:
            try:
                table.add_row([line[0], line[1], line[2]])
            except IndexError:
                table.add_row([line[0], line[1], "No vendor found"])

    print(table)

def tcp_scan(ip: str)-> list:
    port_list = [21, 22, 80, 443, 135, 445, 139]
    open_ports = []
    for port in port_list:
        resp = scapy.sr1(scapy.IP(dst=ip) / scapy.TCP(sport=55555, dport=port, flags='S'), timeout=1, verbose=0)
        if resp != None:
            if(resp.haslayer(scapy.TCP)):
                if(resp.getlayer(scapy.TCP).flags == "SA"):
                    send_rst = scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(sport=55555, dport=port, flags="R"), timeout=1, verbose=0)
                    open_ports.append(port)
    return open_ports if len(open_ports)>0 else "No open ports"

def add_tcp_scan(ip_mac_vendor: list)-> list:
    for ip in ip_mac_vendor:
        open_ports = tcp_scan(ip[0])
        ip.append(open_ports)
    return ip_mac_vendor

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--tcp", help="Perform a TCP scan on online hosts", action='store', nargs="*")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    multiprocessing.set_start_method = 'fork'
    interface_name = choose_interface()
    os.system("clear")
    first_loader = Loader("Getting Network Info")
    first_loader.start() #Reconning Network
    network_info = netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]
    my_ip = network_info["addr"]
    network_addr = calc_network_addr(network_info["addr"], network_info["netmask"]) + "/" + network_info["netmask"]
    network = ipaddress.IPv4Network(network_addr)
    ip_range = get_ip_range(network, my_ip)
    first_loader.stop()
    sweep_loader = Loader("Sweeping IPs")
    sweep_loader.start() #Sweeping IPs
    active_ips = ping_sweep(ip_range)
    sweep_loader.stop()
    info_loader = Loader("Getting Devices Info")
    info_loader.start() #Getting info on actives ips
    ips_and_mac = get_mac_address(active_ips)
    final_table = get_vendor(ips_and_mac)
    info_loader.stop()
    if(args.tcp is not None):
        tcp_loader = Loader("Tcp Scanning")
        tcp_loader.start()
        final_table = add_tcp_scan(final_table)
        tcp_loader.stop()
    pretty_print(final_table, args)