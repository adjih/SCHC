
import serial
import sys
import socket

# XXX: hack
socket.SOL_LORA = "SOL_LORA"
socket.SO_DR = "SO_DR"
socket.SO_CONFIRMED = "SO_CONFIRMED"

class LoRaSerial:
    def __init__(self, devname):
        self.devname = devname
        self.ser = serial.Serial(devname, 115200)

    def get_line(self):
        result = b""
        while True:
            c = self.ser.read(1)
            result +=  c
            if c == b"\n":
                break
            sys.stdout.write(c.decode("utf-8"))
            sys.stdout.flush()
        return result

    def get_line_with(self, match_table):
        while True:
            line = self.get_line()
            print("<%s>" % line)
            for match in match_table.keys():
                if line.find(match) >= 0:
                    return match_table[match]

    def cmd_send(self, raw_data):
        self.get_line_with({b"READ":"ok"})
        print("raw_data", raw_data, type(raw_data))
        hex_data = b"".join([b"%02x" % b for b in raw_data])
        self.ser.write(hex_data+b"\n")
        print("send_as_hex %s" % hex_data)


join_message_table = {
    b"Join procedure succeeded": True,
    b"Join procedure failed": False
}

ser_lora = None

class LoRa:
    LORAWAN = "LoRaWAN"
    OTAA = "over-the air activation"
    def __init__(self, mode):
        self.mode = mode
        global ser_lora
        self.ser = LoRaSerial("/dev/ttyACM0")
        ser_lora = self.ser
        self.joined = False
        
    def join(self, activation=None, auth=None, timeout=None, *args):
        print("--- loramac.join", args)
        self.joined = self.ser.get_line_with(join_message_table)

    def has_joined(self):
        return self.joined


class LoRaSocket:
    def __init__(self):
        pass
    def bind(self, port):
        self.port = port
    def setsockopt(self, *args):
        print("setsockopt(%s)" % repr(args))
    def setblocking(self, blocking):
        print("setblocking(%s)" % repr(blocking))
    def settimeout(self, *args):
        print("settimeout(%s)" % repr(args))
    def send(self, raw_data):
        global ser_lora
        ser_lora.cmd_send(raw_data)
    def recv(self, *args):
        pass

def make_lora_socket():
    return LoRaSocket()
