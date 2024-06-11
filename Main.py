from View import *
from Packet import *

PROTOCOLS = ['arp', 'udp', 'tcp', 'dns', 'icmp', 'icmpv6', 'mdns', 'ssdp', 'igmp', 'tls', 'http']


class Sniffer:
    def __init__(self, gui: MainWindow):
        self.gui = gui
        self.is_start_pressed = False
        self.packets = []
        self.recording_type = ''
        self.is_recording_saved = False
        self.stop_recording = False
        self.packet_count = 0
        self.parameters_list = ['a', False]
        self.is_original = True
        self.check = True
        self.filtered_packets = []
        self.filter = None
        self.setup_gui()
        self.save_file_name = ''

    def setup_gui(self):
        self.gui.start_record.clicked.connect(self.start_sniffing)
        self.gui.stop_record.clicked.connect(self.send_stop_packet)
        self.gui.save_button.clicked.connect(self.save_recording)
        self.gui.import_button.clicked.connect(self.import_recording)
        self.gui.table.itemDoubleClicked.connect(lambda item: self.gui.open_packet_details(item, self.packets))
        self.gui.search_bar.textChanged.connect(self.gui.check_valid_search_term)
        self.gui.search_bar.returnPressed.connect(self.handle_filter_search)
        self.gui.table.horizontalHeader().sectionClicked.connect(self.header_clicked)

    def header_clicked(self, col_num):
        if col_num == 4:  # if parameter is summary, which is not sortable
            return
        parameter_list = ["number", "protocol", "src", "dst"]
        parameter = parameter_list[col_num]
        if self.parameters_list[0] == parameter:
            self.parameters_list[1] = not self.parameters_list[1]
        else:
            self.parameters_list[0] = parameter
            self.parameters_list[1] = False
        self.sort_and_show()

    def handle_filter_search(self):
        if not self.gui.is_search_valid:
            return
        search_string = self.gui.search_bar.text()
        search_string = search_string.replace(' ', '')
        search_list = search_string.split('or')
        self.gui.search_list = search_list
        self.find_matching_packets(search_list)

    def send_stop_packet(self):
        self.stop_recording = True
        self.is_start_pressed = False
        self.check = False
        if not self.is_original:
            self.sort_and_show()
        self.gui.change_record_buttons_color(self.is_start_pressed)

    def stopfilter(self, x):
        return self.stop_recording

    def sniffing(self):
        scapy.config.sniff_promisc = 0
        sniff(filter="arp or tcp or udp or icmp or icmp6", prn=self.process_packet,
              stop_filter=self.stopfilter)

    def process_packet(self, new_packet):
        self.check_if_ended()
        new_packet = self.register_packet(new_packet)
        self.add_packet(new_packet)

    def check_if_ended(self):
        if self.gui.is_closed:
            sys.exit(0)

    def register_packet(self, new_packet):
        self.packet_count += 1
        new_packet = Packet(self.packet_count, new_packet)
        self.packets.append(new_packet)
        return new_packet

    def add_packet(self, new_packet):
        if self.filter is None:
            self.gui.add_to_table(new_packet)
        else:
            self.add_packet_if_matching(new_packet)

    def start_sniffing(self):
        if self.is_start_pressed is False:
            if self.packets != [] and self.is_recording_saved is False and self.recording_type == 'live':
                self.start_recording_again = self.gui.show_popup()
                self.save_file_name = self.gui.save_file_name
                if self.start_recording_again == 0 or self.save_file_name != "":
                    return
                if self.start_recording_again == 1:
                    self.save_recording_to_file()
            self.packet_count = 0
            self.stop_recording = False
            self.clear_packets()
            self.is_original = True  # reset sort parameters
            self.parameters_list = ['a', False]  # reset sort parameters
            self.is_start_pressed = True
            sniff_thread = Thread(target=self.sniffing)

            sniff_thread.start()
            self.gui.change_record_buttons_color(self.is_start_pressed)
            self.recording_type = 'live'
            self.is_recording_saved = False

    def clear_packets(self):
        self.packets = []
        self.gui.clear_table()

    def save_recording(self):
        if not self.is_start_pressed and self.packets != []:
            self.gui.file_save_menu()
            self.save_file_name = self.gui.save_file_name
            if self.save_file_name == "":
                return
            self.save_recording_to_file()
            self.is_recording_saved = True

    def save_recording_to_file(self):
        self.reset_packet_order()
        save_list = [x.info for x in self.packets]
        wrpcap(self.save_file_name, save_list)

    def import_recording(self):
        if self.is_start_pressed:
            return
        if not self.is_recording_saved and self.packets != [] and self.recording_type == 'live':
            self.start_recording_again = self.gui.show_popup()
            self.save_file_name = self.gui.save_file_name
            if (self.start_recording_again == 0 or self.save_file_name == "") and self.start_recording_again != 2:
                return
            if self.start_recording_again == 1:
                self.save_recording_to_file()
        file_name = self.gui.file_import_menu()
        if '.pcap' not in file_name:
            return
        self.clear_packets()
        scapy_cap = rdpcap(file_name)
        self.packet_count = 0
        for packet in scapy_cap:
            self.packet_count += 1
            packet = Packet(self.packet_count, packet)
            self.gui.add_to_table(packet)
            self.packets.append(packet)
        self.recording_type = 'import'

    def sort_and_show(self):
        if self.parameters_list[0] == 'a':
            return
        self.sort_by_parameter()
        self.show_sorted_packets()
        self.is_original = self.parameters_list[0] == "number" and self.parameters_list[1] is False

    def sort_by_parameter(self):
        if not self.filtered_packets:
            self.packets = sorted(self.packets, key=lambda obj: getattr(obj, self.parameters_list[0]),
                                  reverse=self.parameters_list[1])
        else:
            self.filtered_packets = sorted(self.filtered_packets, key=lambda obj: getattr(obj, self.parameters_list[0]),
                                           reverse=self.parameters_list[1])

    def show_sorted_packets(self):
        self.gui.clear_table()
        if not self.filtered_packets:
            for packet in self.packets:
                self.gui.add_to_table(packet)
        else:
            for packet in self.filtered_packets:
                self.gui.add_to_table(packet)

    def reset_packet_order(self):
        temp1 = self.parameters_list[0]
        temp2 = self.parameters_list[1]
        self.parameters_list = ["number", False]
        self.sort_by_parameter()
        self.parameters_list = [temp1, temp2]

    def find_matching_packets(self, search_list: list):
        if search_list == ['']:
            self.filter = None
            self.filtered_packets = []
            self.restore_packets()
            return
        self.filter = search_list
        self.gui.clear_table()
        for packet in self.packets:
            self.add_packet_if_matching(packet)

    def add_packet_if_matching(self, packet):
        if packet.protocol.lower() in self.filter:
            self.filtered_packets.append(packet)
            self.gui.add_to_table(packet)

    def restore_packets(self):
        self.gui.clear_table()
        for packet in self.packets:
            self.gui.add_to_table(packet)


def window():
    # set window and window properties
    app = QApplication(sys.argv)
    win = Sniffer(MainWindow())
    win.gui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    try:
        window()
    except Exception as e:
        print(e.args)
        sys.exit(0)
