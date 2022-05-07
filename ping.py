"""
    Python implementation for ping command
    @Duan, Bin
    CS542 Project
    Adapted from https://github.com/pyping
"""

import os
import select
import signal
import socket
import struct
import sys
import time
import argparse

timer = time.time

# ICMP parameters
ICMP_ECHOREPLY = 0  # Echo reply
ICMP_ECHO = 8  # Echo request
ICMP_MAX_RECV = 2048  # Max size of incoming buffer

MAX_SLEEP = 1000  # Max sleep time


# --------------------------------------------------------------------------
# Classes
# --------------------------------------------------------------------------

class Logging(object):
    """Logging class to record performance statistics and response"""
    def __init__(self):
        self.max_rtt = None
        self.min_rtt = None
        self.avg_rtt = None
        self.packet_lost = None
        self.ret_code = None
        self.ttl = None
        self.output = []

        self.packet_size = None
        self.timeout = None
        self.destination = None
        self.destination_ip = None


class Ping(object):
    """Ping class"""
    def __init__(self, destination, timeout=1000, packet_size=256, own_id=None, logging=True, udp=False,
                 source_address=False):
        self.logging = logging
        if logging:
            self.response = Logging()
            self.response.destination = destination
            self.response.timeout = timeout
            self.response.packet_size = packet_size

        self.destination = destination
        self.timeout = timeout
        self.packet_size = packet_size
        self.udp = udp
        if source_address != False:
            self.source_address = socket.gethostbyname(source_address)

        if own_id is None:
            self.own_id = os.getpid() & 0xFFFF
        else:
            self.own_id = own_id

        try:
            self.dest_ip = to_ip(self.destination)
            if logging:
                self.response.destination_ip = self.dest_ip
        except socket.gaierror as e:
            self.print_unknown_host(e)
        else:
            self.print_start()

        self.seq_number = 0
        self.send_count = 0
        self.receive_count = 0
        self.min_time = 199999
        self.max_time = 0.0
        self.total_time = 0.0

    # --------------------------------------------------------------------------
    # Define message out - print function
    # --------------------------------------------------------------------------

    def print_start(self):
        msg = f'Ping {self.destination} at ({self.dest_ip}): {self.packet_size} data bytes'
        if self.logging:
            self.response.output.append(msg + '\n')
        print(msg)

    def print_unknown_host(self, e):
        msg = f'Ping: Unknown host: {self.destination} at ({e.args[1]})'
        if self.logging:
            self.response.output.append(msg + '\n')
            self.response.ret_code = 1
        print(msg)

        sys.exit(-1)

    def print_success(self, delay, ip, packet_size, ip_header, icmp_header):
        if ip == self.destination:
            from_info = ip
        else:
            from_info = f'{self.destination} ({ip})'

        msg = f'Receive {packet_size} bytes from {from_info}: icmp_seq={icmp_header["seq_number"]} ttl={ip_header["ttl"]} time={delay:.2f} ms'

        if self.logging:
            self.response.output.append(msg + '\n')
            self.response.ret_code = 0
        print(msg)

    def print_failed(self):
        msg = "Request timed out."

        if self.logging:
            self.response.output.append(msg + '\n')
            self.response.ret_code = 1
        print(msg)

    def print_exit(self):
        msg = f'----{self.destination} PING Statistics----'

        if self.logging:
            self.response.output.append(msg + '\n')
        print(msg)

        lost_count = self.send_count - self.receive_count
        lost_rate = float(lost_count) / self.send_count * 100.0

        msg = f'{self.send_count} packets transmitted, {self.receive_count} packets received, {lost_rate:.2f} % packet loss'

        if self.logging:
            self.response.output.append(msg + '\n')
            self.response.packet_lost = lost_count
        print(msg)

        if self.receive_count > 0:
            msg = f'round-trip min/avg/max = {self.min_time:.2f}(ms)/{self.total_time / self.receive_count:.2f}(ms)/{self.max_time:.2f}(ms)'

            if self.logging:
                self.response.min_rtt = f'{self.min_time:.2f}' 
                self.response.avg_rtt = f'{self.total_time / self.receive_count:.2f}'
                self.response.max_rtt = f'{self.max_time:.2f}'
                self.response.ttl = f'{self.ttl}'
                self.response.output.append(msg + '\n')
            print(msg)

    # --------------------------------------------------------------------------
    # Signal handler
    # --------------------------------------------------------------------------

    def signal_handler(self, signum, frame):
        """
        Handle print_exit via signals
        """
        self.print_exit()
        msg = f'(Terminated with signal {signum})\n'

        if self.logging:
            self.response.output.append(msg + '\n')
            self.response.ret_code = 0
        print(msg)

        sys.exit(0)

    def setup_signal_handler(self):
        signal.signal(signal.SIGINT, self.signal_handler) 
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, self.signal_handler)

    # --------------------------------------------------------------------------

    def header2dict(self, names, struct_format, data):
        """ unpack the raw received IP and ICMP header informations to a dict """
        unpacked_data = struct.unpack(struct_format, data)
        return dict(zip(names, unpacked_data))

    # --------------------------------------------------------------------------

    def run(self, count=None, deadline=None):
        """
        send and receive pings in a loop. Stop if count or until deadline.
        """
        if not self.logging:
            self.setup_signal_handler()

        while True:
            delay = self.do_work()

            self.seq_number += 1
            if count and self.seq_number >= count:
                break
            if deadline and self.total_time >= deadline:
                break

            if delay == None:
                delay = 0

            if (MAX_SLEEP > delay):
                time.sleep((MAX_SLEEP - delay) / 1000.0)

        self.print_exit()
        if self.logging:
            return self.response

    def do_work(self):
        """
        Send one ICMP ECHO_REQUEST and receive the response until self.timeout
        """
        try:
            if self.udp:
                current_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname("icmp"))
                if self.source_address:
                    current_socket.bind((self.source_address, 1))
            else:
                current_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        except socket.error as e:
            if e.errno == 1:
                # error trace
                etype, evalue, etb = sys.exc_info()
                evalue = etype(
                    "%s - ICMP messages can only be send from processes running as ROOT/ADMINISTRATOR." % evalue
                )
                raise etype(evalue).with_traceback(etb)
            raise  # raise the original error

        send_time = self.send_one_ping(current_socket)
        if send_time == None:
            return
        self.send_count += 1

        receive_time, packet_size, ip, ip_header, icmp_header = self.receive_one_ping(current_socket)
        current_socket.close()

        if receive_time:
            self.receive_count += 1
            self.ttl = ip_header["ttl"]
            delay = (receive_time - send_time) * 1000.0
            self.total_time += delay
            if self.min_time > delay:
                self.min_time = delay
            if self.max_time < delay:
                self.max_time = delay

            self.print_success(delay, ip, packet_size, ip_header, icmp_header)
            return delay
        else:
            self.print_failed()

    def send_one_ping(self, current_socket):
        """
        Send one ICMP ECHO_REQUEST
        """
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        checksum = 0

        # Make a dummy header with a 0 checksum.
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number)

        padBytes = []
        startVal = 0x42
        for i in range(startVal, startVal + (self.packet_size)):
            padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
        data = bytes(padBytes)

        # Calculate the checksum on the data and the dummy header.
        checksum = calc_cksum(header + data)

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number)

        packet = header + data

        send_time = timer()

        try:
            current_socket.sendto(packet, (self.destination, 1))  # Port number is irrelevant for ICMP
        except socket.error as e:
            self.response.output.append("General failure (%s)" % (e.args[1]))
            current_socket.close()
            return

        return send_time

    def receive_one_ping(self, current_socket):
        """
        Receive the ping from the socket. timeout = in ms
        """
        timeout = self.timeout / 1000.0

        while True:  # Loop while waiting for packet or timeout
            select_start = timer()
            inputready, outputready, exceptready = select.select([current_socket], [], [], timeout)
            select_duration = (timer() - select_start)
            if inputready == []:  # timeout
                return None, 0, 0, 0, 0

            receive_time = timer()

            packet_data, address = current_socket.recvfrom(ICMP_MAX_RECV)

            icmp_header = self.header2dict(
                names=[
                    "type", "code", "checksum",
                    "packet_id", "seq_number"
                ],
                struct_format="!BBHHH",
                data=packet_data[20:28]
            )

            if icmp_header["packet_id"] == self.own_id:  # Our packet
                ip_header = self.header2dict(
                    names=[
                        "version", "type", "length",
                        "id", "flags", "ttl", "protocol",
                        "checksum", "src_ip", "dest_ip"
                    ],
                    struct_format="!BBHHHBBHII",
                    data=packet_data[:20]
                )
                packet_size = len(packet_data) - 28
                ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))

                return receive_time, packet_size, ip, ip_header, icmp_header

            timeout = timeout - select_duration
            if timeout <= 0:
                return None, 0, 0, 0, 0


# --------------------------------------------------------------------------
# Utility Functions
# --------------------------------------------------------------------------
def calc_cksum(src_str):
    """Calculate checksum"""
    total_count = int(len(src_str) / 2) * 2
    sum = 0

    for i in range(0, total_count, 2):
        if (sys.byteorder == "little"):
            low_byte = src_str[i]
            high_byte = src_str[i + 1]
        else:
            low_byte = src_str[i + 1]
            high_byte = src_str[i]
        sum = sum + high_byte * 256 + low_byte

    # Handle last byte if applicable (odd-number of bytes)
    if total_count < len(src_str):
        low_byte = src_str[len(src_str) - 1]
        sum += low_byte

    # Truncate sum to 32 bits
    sum &= 0xffffffff

    # Add high 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum & 0xffff

    # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer


def to_ip(addr):
    """interpolate hostname to valid IPV4 address"""
    def is_valid_ip4_address(addr):
        parts = addr.split(".")
        if not len(parts) == 4:
            return False
        for part in parts:
            try:
                number = int(part)
            except ValueError:
                return False
            if number > 255:
                return False
        return True

    if is_valid_ip4_address(addr):
        return addr
    return socket.gethostbyname(addr)


def ping(args):
    hostname = args.hostname
    timeout = args.timeout
    count = args.count
    packet_size = args.packet_size
    log_file = args.log_file
    p = Ping(hostname, timeout, packet_size)
    response = p.run(count)

    with open(log_file, 'a+') as f:
        f.writelines(response.output)


def print_options(opt):
    """Print options
    It will print both current options and default values(if different).
    """
    msg = ''
    msg += '------------ Ping Options ---------------\n'
    for k, v in sorted(vars(opt).items()):
        comment = ''
        default = parser.get_default(k)
        if v != default:
            comment = f'\t[default: {default}]'
        msg += f'{str(k):>25}: {str(v):<30}{comment}\n'
    
    msg += '----------------- End -------------------'
    print(msg)


def plot_ping(args):
    hostname = args.hostname
    timeout = args.timeout
    packet_size = args.packet_size

    min_time = []
    avg_time = []
    max_time = []
    for count in range(1, 10):
        p = Ping(hostname, timeout, packet_size)
        response = p.run(count)
        del p

        min_time.append(float(response.min_rtt))
        avg_time.append(0.5 * float(response.min_rtt) + 0.5 * float(response.max_rtt))
        max_time.append(float(response.max_rtt))

    import matplotlib.pyplot as plt
    plt.plot(range(1, 10), min_time, label='min_time')
    plt.plot(range(1, 10), avg_time, label='avg_time')
    plt.plot(range(1, 10), max_time, label='max_time')

    plt.legend()
    plt.title("min/avg/max round-trip time of different counts")
    plt.ylabel("time")
    plt.xlabel("count")
    plt.show()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ping Command Python Implementation for CS542 Project.")

    parser.add_argument("--hostname", type=str, default="www.google.com", help="Address to be pinged.")
    parser.add_argument("--log_file", type=str, default="log.txt", help="Path to save ping log.")
    parser.add_argument("--timeout", type=int, default=1000, help="timeout for receiving a ping (ms).")
    parser.add_argument("--count", type=int, default=2, help="How many ICMP requests constantly.")
    parser.add_argument("--packet_size", type=int, default=256, help="Packet size.")
    parser.add_argument('--test', action='store_true', default=False, help='test the ping program')

    opt = parser.parse_args()
    print_options(opt)
    if opt.test:
        plot_ping(opt)
    else:
        ping(opt)
