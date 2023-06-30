#!/usr/bin/env python3

import customtkinter as ctk,dpkt,socket,matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter import filedialog
from scapy.all import *

source_ips = []
destination_ips = []
source_macs = []
destination_macs = []
source_ports = []
destination_ports = []

def forget(par):
    par.place_forget()
    print('erased-'+str(par))

def extract_packet_info(packet):
    eth = packet
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            transport = ip.data
            protocol = 'TCP'
            source_port = transport.sport
            destination_port = transport.dport
        elif isinstance(ip.data, dpkt.udp.UDP):
            transport = ip.data
            protocol = 'UDP'
            source_port = transport.sport
            destination_port = transport.dport
        else:
            protocol = 'Unknown'
            source_port = 'Unknown'
            destination_port = 'Unknown'
        
        source_ip = socket.inet_ntoa(ip.src)
        destination_ip = socket.inet_ntoa(ip.dst)
        source_mac = ':'.join('%02x' % b for b in eth.src)
        destination_mac = ':'.join('%02x' % b for b in eth.dst)

        source_ips.append(source_ip)
        destination_ips.append(destination_ip)
        source_macs.append(source_mac)
        destination_macs.append(destination_mac)
        source_ports.append(source_port)
        destination_ports.append(destination_port)

    elif isinstance(eth.data, dpkt.arp.ARP):
        arp = eth.data
        source_ip = socket.inet_ntoa(arp.spa)
        destination_ip = socket.inet_ntoa(arp.tpa)
        source_mac = ':'.join('%02x' % b for b in eth.src)
        destination_mac = ':'.join('%02x' % b for b in eth.dst)
        
        source_ips.append(source_ip)
        destination_ips.append(destination_ip)
        source_macs.append(source_mac)
        destination_macs.append(destination_mac)
        source_ports.append(source_port)
        destination_ports.append(destination_port)
    
def convert_to_json(file_path):
    global source_ips, destination_ips, source_macs, destination_macs, source_ports, destination_ports
    source_ips.clear()
    destination_ips.clear()
    source_macs.clear()
    destination_macs.clear()
    source_ports.clear()
    destination_ports.clear()

    with open(file_path, 'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        for timestamp, packet_data in pcap:
            eth = dpkt.ethernet.Ethernet(packet_data)
            if type(eth.data) != dpkt.ip.IP:
                continue
            ip = eth.data
            if type(ip.data) != dpkt.tcp.TCP:
                continue
            try:
                eth = dpkt.ethernet.Ethernet(packet_data)
                extract_packet_info(eth)
            except dpkt.dpkt.NeedData:
                continue

def navigator(home,mast):
    print('plot graphs')
    forget(home)
    Graph(mast)

def browse_file(label,home,mast):
    print('browsing')
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        if file_path.lower().endswith('.pcap'):
            convert_to_json(file_path)
        else:
            label.configure(text='Invalid file, please upload a pcap file')
    else:
        print('canceled')
        return
    print('browsed')
    navigator(home,mast)

class Home(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.place(x=0, y=0, relwidth=1, relheight=1)
        self.create_wid(parent)

    def create_wid(self, parent):
        label = ctk.CTkLabel(self, text='Select a Pcap file',
                             text_color='white', corner_radius=10)
        label.pack(anchor='center', pady=20)

        btn = ctk.CTkButton(self, text='Browse', fg_color='#FF0', text_color='#000',
                            hover_color='#AA0', corner_radius=10, command=lambda: browse_file(label,self,parent))
        btn.pack(pady=10)

class Graph(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)

        notepad = self.tab_view = MyTabView(master=parent)
        notepad.place(x=0, y=0, relwidth=1, relheight=1)

def create_pie(lists,name,mast,r,c):
    ipCount = {}
    for ip in lists:
        ipCount[ip] = ipCount.get(ip, 0) + 1
    
    labels = list(ipCount.keys())
    data = list(ipCount.values())

    fig, ax = plt.subplots()
    ax.pie(data, labels=labels, autopct='%1.1f%%')
    ax.axis('equal')
    ax.set_title(name)

    canvas = FigureCanvasTkAgg(fig, master=mast)
    canvas.draw()
    canvas.get_tk_widget().grid(row=r, column=c, padx=5, pady=5)
    
def create_hist(lists,name,mast,r,c):
    macCount = {}
    for mac in lists:
        macCount[mac] = macCount.get(mac, 0) + 1

    labels = list(macCount.keys())
    data = list(macCount.values())

    fig, ax = plt.subplots()
    ax.barh(labels, data)

    ax.set_xlabel('Occurrences')
    ax.set_title(name)
    canvas = FigureCanvasTkAgg(fig, master=mast)
    canvas.draw()
    canvas.get_tk_widget().grid(row=r, column=c, padx=5, pady=5)

def create_port_hist(lists,name,mast,r,c):
    portCount = {}
    for port in lists:
        portCount[port] = portCount.get(port, 0) + 1

    # Prepare the data for the horizontal histogram
    labels = [str(port) for port in portCount.keys()]
    data = list(portCount.values())

    # Create the horizontal histogram
    fig, ax = plt.subplots()
    ax.barh(labels, data)

    # Set labels and title
    ax.set_xlabel('Occurrences')
    ax.set_ylabel('Port Number')
    ax.set_title('Port Number Distribution')
    canvas = FigureCanvasTkAgg(fig, master=mast)
    canvas.draw()
    canvas.get_tk_widget().grid(row=r, column=c, padx=5, pady=5)

def reupload(tab,mast):
    print('reup')
    forget(tab)
    Home(mast)
    print('done')

class MyTabView(ctk.CTkTabview):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        # create tabs
        self.add("pie charts")
        self.add("Histograms")
        self.add("upload")

        # add widgets on tabs
        #pie
        create_pie(source_ips,'Source Ip',self.tab("pie charts"),0,0)
        create_pie(destination_ips,'destination_ips',self.tab("pie charts"),0,1)
        create_pie(source_macs,'source macs',self.tab("pie charts"),0,2)
        create_pie(destination_macs,'destination macs',self.tab("pie charts"),1,0)
        create_pie(source_ports,'source ports',self.tab("pie charts"),1,1)
        create_pie(destination_ports,'destination ports',self.tab("pie charts"),1,2)
        
        #histo
        create_hist(source_ips,'Source Ip',self.tab("Histograms"),0,0)
        create_hist(destination_ips,'destination ips',self.tab("Histograms"),0,1)
        create_hist(source_macs,'source macs',self.tab("Histograms"),0,2)
        create_hist(destination_macs,'destination macs',self.tab("Histograms"),1,0)
        create_port_hist(source_ports,'source ports',self.tab("Histograms"),1,1)
        create_port_hist(destination_ports,'destination ports',self.tab("Histograms"),1,2)

        #upload
        btn = ctk.CTkButton(master=self.tab("upload"), text='Reupload', fg_color='#FF0', text_color='#000',hover_color='#AA0', corner_radius=10, command=lambda: reupload(self,master))
        btn.pack(pady=10)

class App(ctk.CTk):
    def __init__(self, title, size):
        super().__init__()

        # attributes
        self.title(title)
        self.geometry(f'{size[0]}x{size[1]}')
        self.minsize(size[0], size[1])

        self.attributes('-fullscreen', False)
        # widgets
        self.home = Home(self)
        self.bind('<Escape>', lambda event: self.quit())
        self.mainloop()

App('pcap file reader', (600, 500))
