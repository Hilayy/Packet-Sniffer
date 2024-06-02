from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.tls import *
from scapy.contrib.igmp import IGMP
TCP_FLAGS = {'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'P': 'PSH', 'R': 'RST', 'U': 'URG'}
DHCP_TYPES = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Decline'}
IGMP_TYPES = {
    1: {17: "Membership Query", 18: "Membership Report"},
    2: {17: "Membership Query", 22: "Membership Report", 23: "Leave Group"},
    3: {17: "Membership Query, general", 18: "Membership Query, group-specific",
        19: "Membership Reduction Message", 34: "Membership Report (Join)",
        35: "Membership Report (Leave)"}}
TLS_VERSIONS = {b'\x03\x01': '1', b'\x03\x02': '1.1', b'\x03\x03': '1.2', b'\x03\x04': '1.3'}
TLS_TYPES = {20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat'}

class Packet:
    def __init__(self, count : int, packet_body):
        self.number = count
        self.info = packet_body
        self.length = self.__get_length()
        self.protocol = self.__get_protocol()
        self.src, self.dst = self.__get_ends()
        self.summary = ""
        self.__configure_get_summary()

    def __get_length(self):
        return len(self.info)

    def __get_protocol(self):
        if self.info.haslayer(TCP):
            if self.info.haslayer(Raw):
                raw_data = self.info.getlayer(Raw).load
                version = raw_data[1:3]
                if version in TLS_VERSIONS.keys():
                    return "TLSv" + TLS_VERSIONS[version]
        if TCP in self.info and self.info.haslayer(Raw):
            raw_data = self.info[Raw].load.decode('utf-8', 'ignore')
            if "HTTP" in raw_data:
                return "HTTP"
        if UDP in self.info:
            if self.info[UDP].dport == 1900 or self.info[UDP].sport == 1900:
                return "SSDP"
        if ICMP in self.info:
            return "ICMP"
        if IPv6 in self.info:
            if self.info[IPv6].nh == 58:
                return "ICMPv6"
        if "DHCP" in str(self.info):
            if self.info[UDP].sport == 546 or self.info[UDP].sport == 547:
                return "DHCPv6"
            return "DHCP"
        if IP in self.info:
            proto_number = self.info[IP].proto
            if proto_number == 2:
                return "IGMPv2"
            if proto_number == 58:
                return "IGMPv3"
        if UDP in self.info:
            if self.info[UDP].dport == 5353:
                return "MDNS"
        if "DNS" in str(self.info):
            return "DNS"
        if TCP in self.info:
            return "TCP"
        if UDP in self.info:
            return "UDP"
        if IP in self.info or IPv6 in self.info:
            return "UNKNOWN"
        return "ARP"

    def __get_ends(self):
        if IPv6 in self.info:
            return self.info[IPv6].src, self.info[IPv6].dst
        if IP in self.info:
            return self.info[IP].src, self.info[IP].dst
        return self.info.src, self.info.dst if self.info.dst != 'ff:ff:ff:ff:ff:ff' else 'Broadcast'

    def __configure_get_summary(self):
        if self.protocol == "ARP":
            self.__get_summary_arp()
        if self.protocol == "UDP":
            self.__get_summary_udp()
        if self.protocol == "TCP":
            self.__get_summary_tcp()
        if self.protocol == "DNS":
            self.__get_summary_dns()
        if self.protocol == "ICMP":
            self.__get_summary_icmp()
        if self.protocol == "ICMPv6":
            self.__get_summary_icmp6()
        if self.protocol == "MDNS":
            self.__get_summary_mdns()
        if "DHCP" in self.protocol:
            self.__get_summary_dhcp()
        if self.protocol == "SSDP":
            self.__get_summary_ssdp()
        if "IGMP" in self.protocol:
            self.__get_summary_igmp()
        if "TLS" in self.protocol:
            self.__get_summary_tls()
        if self.protocol == "HTTP":
            self.__get_summary_http()

    def __get_summary_arp(self):
        opcode = self.info.op
        summary_string = ""
        if opcode == 1:
            requested_ip = self.info.pdst
            tell_to_ip = self.info.psrc
            summary_string = f"Who has {requested_ip}? Tell {tell_to_ip}"
        if opcode == 2:
            requested_ip_answer = self.info.psrc
            mac_of_ip = self.info.hwsrc
            summary_string = f"{requested_ip_answer} is at {mac_of_ip}"
        self.summary = summary_string

    def __get_summary_udp(self):
        udp_segment = self.info[UDP]
        payload_size = len(udp_segment)
        source_port = udp_segment.sport
        destination_port = udp_segment.dport
        summary_string = f"{source_port} -> {destination_port}, Payload size: {payload_size}"
        self.summary = summary_string

    def __get_summary_tcp(self):
        tcp_segment = self.info[TCP]
        payload_size = len(tcp_segment)
        source_port = tcp_segment.sport
        destination_port = tcp_segment.dport
        flags = tcp_segment.flags
        flags_string_list = []
        for flag in flags:
            flags_string_list.append(TCP_FLAGS[flag])
        flags_string = ", ".join(flags_string_list)
        summary_string = f"{source_port} -> {destination_port}, [{flags_string}], Payload size: {payload_size} "
        self.summary = summary_string

    def __get_summary_dns(self):
        dns_segment = self.info[DNS]
        summary_string = ""
        if dns_segment.opcode == 0:
            if dns_segment.qr == 0:
                summary_string = "Standard Query"
            else:
                summary_string = "Standard Query Response"
        if dns_segment.opcode == 4:
            summary_string = "Notify"
        if dns_segment.opcode == 5:
            summary_string = "Update"
        is_error = dns_segment.rcode != 0
        if is_error:
            summary_string = "DNS Error"
        self.summary = summary_string

    def __get_summary_icmp(self):
        icmp_segment = self.info[ICMP]
        pattern = r'type {1,}=.{1,}'
        icmp_type_text = re.findall(pattern, icmp_segment.show(dump=True))[0]
        icmp_type_text = icmp_type_text[icmp_type_text.index('=') + 2:]
        icmp_type_text = icmp_type_text.replace('-', ' ')
        icmp_type_text = icmp_type_text.title()
        ip_segment = self.info[IP]
        ttl = ip_segment.ttl
        summary_string = f"{icmp_type_text}, ttl: {ttl}"
        self.summary = summary_string

    def __get_summary_icmp6(self):
        pattern = r'type {1,}=.{1,}'
        icmp6_type_text = re.findall(pattern, self.info.show(dump=True))[1]
        icmp6_type_text = icmp6_type_text[icmp6_type_text.index('=') + 2:]
        self.summary = icmp6_type_text

    def __get_summary_mdns(self):
        summary_string = ""
        if self.info[DNS].qr == 0:
            summary_string = "Query"
        else:
            summary_string = "Query Response"
        self.summary = summary_string

    def __get_summary_dhcp(self):
        summary_string = ""
        if self.info.haslayer(DHCP):
            options = self.info[DHCP].options
            for option in options:
                if option[0] == 'message-type':
                    summary_string = "DHCP " + DHCP_TYPES[option[1]]
        else:
            dhcp6_fields = str(self.info)
            dhcp6_type = dhcp6_fields.split('/')[3]
            dhcp6_type = "DHCPv6 " + dhcp6_type[7:]
            self.summary = dhcp6_type

    def __get_summary_ssdp(self):
        summary_string = ""
        payload = self.info.load.decode('utf-8', 'ignore')
        summary_string = payload.splitlines()[0]
        self.summary = summary_string

    def __get_summary_igmp(self):
        igmp_version = int(self.protocol[-1])
        summary_string = ""
        igmp_type = self.info[IGMP].type
        try:
            summary_string = IGMP_TYPES[igmp_version][igmp_type]
        except Exception:
            summary_string = ""
        self.summary = summary_string

    def __get_summary_tls(self):
        summary_string = ""
        raw_data = self.info.getlayer(Raw).load
        type_field = raw_data[0]
        if type_field in TLS_TYPES.keys():
            summary_string += TLS_TYPES[type_field]
        if type_field == 22:  # handshake
            if raw_data[5] == 1:
                summary_string = "Client Hello"
            else:
                summary_string = "Server Hello"
        self.summary = summary_string

    def __get_summary_http(self):
        http_data = self.info.getlayer(Raw).load.decode('utf-8', 'ignore')
        self.summary = http_data.splitlines()[0]

    def get_layer_info(self):
        layers_dict = {}
        pattern = r'###\[.{1,}]###'
        show = self.info.show(dump=True)
        layers = [x[5:-5] for x in re.findall(pattern, show)]
        parts = re.split(pattern, show)[1:]  # 0 index in None
        layers_dict['Ethernet'] = parts[0]
        layers_dict[layers[1]] = parts[1]
        return layers_dict
