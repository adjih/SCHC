#! /usr/bin/env python3
#---------------------------------------------------------------------------

import logging
import threading
import argparse

import json
import base64, binascii
import struct

import select
import socket
import time
import sched

import warnings
import requests

import bottle # pip install bottle || wget https://bottlepy.org/bottle.py
from bottle import post, request, response

try:
    import tornado.ioloop
    import tornado.web
    with_tornado = True
except:
    print("cannot import tornado")
    with_tornado = False

import sys
sys.path.append("../../PLIDO-tanupoo")
import fragment
    
#---------------------------------------------------------------------------

def bytes_to_hex(data, with_new_line=False, with_repr=True):
    result = ""
    for i,b in enumerate(bytearray(data)):
        if i == 0:
            pass
        elif i%16 == 0:
            if with_new_line:
                result += "\n"
            else: result += " "
        else: result += " "
        result += "%02x" % b
    if with_repr:
        result += " "+repr(data)
    return result

#---------------------------------------------------------------------------

class FragmentationManager:
    """The fragmentation manager handles the logic of the fragment sending etc.
    """
    
    def __init__(self):
        self.nb_bit_bitmap = 1
        self.max_fcn_per_window = self.nb_bit_bitmap - 1 # included
        
        self.window = 0
        self.fcn = self.max_fcn_per_window # protocol FCN
        self.fragment_index = 0 #
        self.content = None
        self.state = "init"

    def event_packet(self, raw_packet):
        if self.state == "init":
            print("(ignored) Dev. packet:", repr(raw_packet))
            self.state = "fragment"
            self.content = ["to be", "or not to", " be, that's", "the question"]
            return self.get_current_fragment()
        elif self.state == "fragment":
            return self.process_ack(raw_packet)
        else: raise ValueError("bad state", self.state)

    def get_current_fragment(self):
        print("fragment window={} fcn={} current_frag_index={}".format(
            self.window, self.fcn, self.fragment_index))
        header = struct.pack(b"!BB", self.window, self.fcn)
        return header + bytes(self.content[self.fragment_index].encode("ascii"))

    def process_ack(self, raw_packet):
        print("process_ack", bytes_to_hex(raw_packet))
        if len(raw_packet) != struct.calcsize("!BB"):
            print("XXX: bad ack size", len(raw_packet))
            return b"XXX:bad"
        window, bitmap = struct.unpack("!BB", raw_packet)
        print("window={}, bitmap={}".format(window, bitmap))
        if window != self.window:
            print("warning: bad window number", window, self.window)
            return b"XXX:bad-window"
        if bitmap != 1: #XXX
            print("warning: incomplete bitmap", bitmap, 1)
            return b"XXX:bad-bitmap"

        # Next fragment
        self.window = (self.window+1) % 2 # protocol
        # - because it will be the first of the new window:
        self.fcn = self.max_fcn_per_window 
        self.fragment_index += 1 # internal data structure

        if self.fragment_index == len(self.content):
            print("Finished trasnmission of fragments")
            return b""

        if self.fragment_index == len(self.content)-1:
            # protocol - because it is the end of the content in this case:
            self.fcn = 1 
            return self.get_current_fragment() # XXX + "MIC"
        else:
            return self.get_current_fragment()

#---------------------------------------------------------------------------

# FRAGMENT_FORMAT = {
#     # 0|0|12345678|12345678
#     "hdr_size": 16,
#     "rid_size": 0,
#     "rid_shift": 0,
#     "rid_mask": 0x0000,
#     "dtag_size": 0,
#     "dtag_shift": 0,
#     "dtag_mask": 0x0000,
#     "win_size": 1,
#     "win_shift": 8,
#     "win_mask": 0x0100,
#     "fcn_size": 1,
#     "fcn_shift": 0,
#     "fcn_mask": 0x01,
#     }

FRAGMENT_FORMAT = fragment.fp_ietf100_win

class SystemManager:
    def add_event(self, rel_time, callback, args):
        XXX

    def send_packet(self, packet):
        XXX

# {'srcbuf': b'The crow has flown away:\nswaying in the evening sun,\naleafless tree.', 'max_fcn': 255, 'win_size': 255, 'win_mask': 57896044618658097711785492504343953926634992332820282019728792003956564819967, 'fcn': 255, 'end_of_fragment': 255, 'base_hdr': 256}

INTER_FRAGMENT_DELAY = 1.0 # seconds
WAIT_BITMAP_TIMEOUT = 5.0 # seconds

class WindowAckModeManager:
    """The fragmentation manager handles the logic of the fragment sending etc.
    """
    
    def __init__(self, system_manager, fragment_format, full_packet,
                 rule_id, dtag, window_size, fragment_size):
        self.system_manager = system_manager
        fragment.fp = fragment_format #XXX: hack
        self.fragment = fragment.fragment(
            srcbuf=full_packet, rule_id=rule_id, dtag=dtag,
            noack=False, window_size=window_size)
        print(self.fragment.__dict__) #XXX
        self.fragment_size = fragment_size

        self.nb_fragment = (len(full_packet) + fragment_size-1) // fragment_size

        # 1376     Intially, when a fragmented packet need to be sent, the window is set
        # 1377     to 0, a local_bit map is set to 0, and FCN is set the the highest
        # 1378     possible value depending on the number of fragment that will be sent
        # 1379     in the window (INIT STATE).
        self.state = "INIT"
        self.window = 0
        self.window_index = 0
        self.bitmap = 0
        # Note: we need to know the number of fragments beforehand
        self.init_duplicate(full_packet, window_size)

        print("STATE INIT, fragmentation parameters:")
        print("  nb_fragment={}".format(self.nb_fragment))
        print("  fragment_size={}".format(fragment_size))
        print("  initial fcn={}".format(self.fcn))

    def init_duplicate(self, full_packet, window_size):
        # (some of these variables are duplicates of the class fragment.fragment)
        BITMAP_SIZE = 8 # bits
        self.max_fcn = 6
        self.fcn_all_1 = 7 
        #self.fcn = min(self.nb_fragment, self.fragment.max_fcn) # XXX
        self.fcn = min(self.nb_fragment, self.max_fcn)        
        self.full_packet = full_packet
        self.position = 0
        self.window_size = window_size

    def get_next_fragment(self): # XXX: temporary version
        warnings.warn("XXX:no RuleId, DTag & hardwired sizes, constants")
        FCN_ALL_1 = 0xff
        fragment_content = self.full_packet[self.position:self.position+self.fragment_size]
        self.position += self.fragment_size
        
        unfinished = not self.is_finished()
        if unfinished:
            afcn = self.fcn
        else: afcn = self.fcn_all_1
        fragment_hdr = struct.pack("!BB", self.window, afcn)
        return unfinished, fragment_hdr+fragment_content

    def send_empty_fragment(self):
        # 1410	   In ACK Always, if the timer expire, an empty All-0 (or All-1 if the
        # 1411	   last fragment has been sent) fragment is sent to ask the receiver to        
        warnings.warn("XXX:no RuleId, DTag & hardwired sizes, constants")
        unfinished = not self.is_finished()
        if unfinished:
            afcn = 0 # ALL_0
        else: afcn = self.fcn_all_1
        
        empty_fragment = struct.pack("!BB", self.window, afcn)
        self.system_manager.send_packet(empty_fragment)

    def is_finished(self):
        return not (self.position < len(self.full_packet))
        
    def get_next_fragment_real(self):
        return self.fragment.next_fragment(self.fragment_size)

    def start(self):
        assert self.state == "INIT"
        self.state = "SEND"
        unfinished, packet = self.get_next_fragment()
        self.send_fragment_and_prepare_next(packet, unfinished)

    def send_fragment_and_prepare_next(self, packet, unfinished):
        assert self.state == "SEND"
        self.system_manager.send_packet(packet)

        # 1384	   regulation rules or constraints imposed by the applications.  Each
        # 1385	   time a fragment is sent the FCN is decreased of one value and the
        # 1386	   bitmap is set.  The send state can be leaved for different reasons
        self.bitmap = self.bitmap | (1<<self.fcn)
        
        if self.fcn == 0:
            # 1386	   bitmap is set.  The send state can be leaved for different reasons
            # 1387	   (for both reasons it goes to WAIT BITMAP STATE):
            self.state = "WAIT BITMAP"
            
            if unfinished:
                # 1471	   [...] FCN==0 & more frags [...]
                # 1389	   o  The FCN reaches value 0 and there are more fragments.  In that
                # 1390	      case an all-0 fragmet is sent and the timer is set.  The sender
                # 1391	      will wait for the bitmap acknowledged by the receiver.
                self.system_manager.add_event(
                    WAIT_BITMAP_TIMEOUT,
                    self.event_wait_bitmap_timeout_check, (self.window, False))
            else:
                # 1471	   [...] last frag [...]
                # 1393	   o  The last fragment is sent.  In that case an all-1 fragment with
                # 1394	      the MIC is sent and the sender will wait for the bitmap
                # 1395	      acknowledged by the receiver.  The sender set a timer to wait for
                # 1396	      the ack.
                warnings.warn("XXX:should add MIC")
                self.system_manager.add_event(
                    WAIT_BITMAP_TIMEOUT,
                    self.event_wait_bitmap_timeout_check, (self.window, True))
        else:
            self.fcn -= 1
            self.system_manager.add_event(
                INTER_FRAGMENT_DELAY, self.event_next_fragment, ())

    def event_next_fragment(self):
        assert self.state == "SEND"
        # 1464	[...] send Window + frag(FCN)
        unfinished, packet = self.get_next_fragment()
        self.send_fragment_and_prepare_next(packet, unfinished)
        
    def event_wait_bitmap_timeout_check(self, window_index, final):
        assert window_index <= self.window_index
        if window_index != self.window_index:
            return # not really a time out (as window_index as progressed)
        assert self.state == "WAIT BITMAP"
        # 1410	   In ACK Always, if the timer expire, an empty All-0 (or All-1 if the
        # 1411	   last fragment has been sent) fragment is sent to ask the receiver to
        # 1412	   resent its bitmap.  The window number is not changed.
        print("WAIT BITMAP: timeout")
        warnings.warn("XXX:should implement MAX_ATTEMPTS")
        self.send_empty_fragment()
        self.system_manager.add_event(
            WAIT_BITMAP_TIMEOUT,
            self.event_wait_bitmap_timeout_check, (self.window, True))

    def event_packet(self, raw_packet):
        #print("RECEIVE", raw_packet)
        if self.state == "INIT":
            print("ERROR: unexpected packet in state INIT", raw_packet)
            return
        elif self.state == "SEND":
            print("ERROR: unexpected packet in state SEND", raw_packet)
            return
        elif self.state == "WAIT BITMAP":
            # XXX:how do we know the packet format?:
            self.process_ack(raw_packet)
        else: raise RuntimeError("unexpected state", self.state)

    def process_ack(self, raw_packet):
        warnings.warn("XXX:hardwired formats, sizes, constants")
        window, bitmap = struct.unpack(b"!BB", raw_packet)
        bitmap = bitmap >> 1 # XXX - only for hardcoded case
        print("ACK", window, bitmap, self.bitmap)
        # 1662	   If the window number on the received bitmap is correct, the sender
        if window != self.window:
            print("ERROR: bad window number", window, self.window)
            return
        if bitmap & ~self.bitmap != 0: 
            print("ERROR: inconsistent bitmap", bitmap, self.bitmap)
            # XXX: what to do? - should not happen except for last
            return

        resend_bitmap = self.bitmap & ~bitmap
        if resend_bitmap == 0:
            # 1662	   If the window number on the received bitmap is correct, the sender
            # 1663	   compare the local bitmap with the received bitmap.  If they are equal
            # 1664	   all the fragments sent during the window have been well received.  If
            
            if not self.is_finished():
                # 1665	   at least one fragment need to be sent, the sender clear the bitmap,
                # 1666	   stop the timer and move its sending window to the next value.  If no
                
                # XXX: (optional) stop timer
                self.window_index += 1
                self.window = self.window+1 # XXX!!: modulo
                nb_remaining_fragment = (self.nb_fragment
                                         - self.window_size * self.window_index)
                print("UPDATE:", nb_remaining_fragment, self.nb_fragment,
                      self.window_size, self.window_index)
                self.fcn = min(nb_remaining_fragment, self.max_fcn) # XXX:factor in
                unfinished, packet = self.get_next_fragment()
                self.state = "SEND"                
                self.send_fragment_and_prepare_next(packet, unfinished)

            else:
                # 1667	   more fragments have to be sent, then the fragmented packet
                # 1668	   transmission is terminated.
                self.state = "END"
                self.event_transmission_completed()
                
        else:
            # 1670	   If some fragments are missing (not set in the bit map) then the
            # 1671	   sender resend the missing fragments.  When the retransmission is
            # 1672	   finished, it start listening to the bitmap (even if a All-0 or All-1
            # 1673	   has not been sent during the retransmission) and returns to the
            # 1674	   waiting bitmap state.

            # 1685	   If the local-bitmap is different from the received bitmap the counter
            # 1686	   Attemps is increased and the sender resend the missing fragments
            # 1687	   again, when a MAX_ATTEMPS is reached the sender sends an Abort and
            # 1688	   goes to error.
            raise NotImplementedError("XXX not implemented yet, sorry")

    def event_transmission_completed(self):
        print("transmssion completed")
        
    def get_current_fragment(self):
        print("fragment window={} fcn={} current_frag_index={}".format(
            self.window, self.fcn, self.fragment_index))
        header = struct.pack(b"!BB", self.window, self.fcn)
        return header + bytes(self.content[self.fragment_index].encode("ascii"))

    def process_ack_old(self, raw_packet):
        # Next fragment
        self.window = (self.window+1) % 2 # protocol
        self.fcn = self.max_fcn_per_window # - because it will be the first of the new window
        self.fragment_index += 1 # internal data structure

        if self.fragment_index == len(self.content):
            print("Finished trasnmission of fragments")
            return b""

        if self.fragment_index == len(self.content)-1:
            self.fcn = 1 # protocol - because it is the end of the content in this case
            return self.get_current_fragment() # XXX + "MIC"
        else:
            return self.get_current_fragment()


class SimulSystemManager:
    def __init__(self, send_callback=None):
        self.scheduler = sched.scheduler(self.get_clock, self.wait_delay)
        self.clock = 0
        self.send_callback = send_callback

    # sched.scheduler API
        
    def get_clock(self):
        return self.clock

    def wait_delay(self, delay):
        self.clock += delay

    def run(self):
        self.scheduler.run()

    # external API
        
    def add_event(self, rel_time, callback, args):
        self.scheduler.enter(rel_time, 0, callback, args)

    def send_packet(self, packet):
        print("SEND:", bytes_to_hex(packet))
        if self.send_callback != None:
            self.send_callback()
            
class RealTimeSystemManager:
    """
    Manage event queue in real time
    Send and receive packet from an UDP port
    """
    def __init__(self, dest_address_and_port, listen_port=None, time_scale=1):
        self.time_t0 = time.time()
        self.time_scale = time_scale
        self.receive_packet_callback = None
        self.scheduler = sched.scheduler(self.get_clock, self.wait_delay)
        self.destination = dest_address_and_port
        
        self.sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if listen_port == None:
            unused, listen_port = dest_address_and_port
        print("UDP listening on port {}".format(listen_port))
        self.sd.bind(("", listen_port))
        
        self.add_event(1e8, "should not be called", ())
        self.inject_receive_done = False
        self.inject_receive_list = []


    def set_inject_receive_list(self, packet_list):
        self.inject_receive_list = packet_list[:]

    def set_receive_packet_callback(self, callback):
        self.receive_packet_callback = callback
        
    def get_clock(self):
        return self.time_t0 + (time.time()-self.time_t0) * self.time_scale

    def wait_delay(self, delay):
        #delay *= self.time_scale
        # Note: we might wait for less time than expected if packet received
        if len(self.inject_receive_list) > 0 and not self.inject_receive_done:
            inject_packet = self.inject_receive_list.pop(0)
            self.inject_receive_done = True
            if inject_packet != None and self.receive_packet_callback != None:
                print("injected packet:", inject_packet)
                self.receive_packet_callback(inject_packet)
                return

        read_list,unused,unused = select.select([self.sd],[],[], delay)
        self.inject_receive_done = False
        if len(read_list) > 0:
            assert read_list[0] is self.sd
            port = self.destination[1]
            packet, address_and_port = self.sd.recvfrom(2**16)
            if self.receive_packet_callback != None:
                self.receive_packet_callback(packet)

    def run(self):
        self.scheduler.run()
        
    def add_event(self, rel_time, callback, args):
        self.scheduler.enter(rel_time, 0, callback, args)

    def send_packet(self, packet):
        print("SEND:", bytes_to_hex(packet))
        self.sd.sendto(packet, self.destination)


def test_real_time_system_manager(args):
    system = RealTimeSystemManager((args.address, args.port), args.listen_port)
    start_time = time.time()
    def periodic_display_function():
        elapsed_time = system.get_clock()-start_time
        print("current time={} - display".format(elapsed_time))
        system.add_event(1.5, periodic_display_function, ())
    def periodic_send_function():
        elapsed_time = system.get_clock()-start_time
        print("current time={} - send".format(elapsed_time))
        system.send_packet("<packet from {}>".format(elapsed_time))
        system.add_event(2, periodic_send_function, ())
    system.add_event(0, periodic_display_function, ())
    system.add_event(0, periodic_send_function, ())    
    system.run()

        
def test_window_ack_manager_internal():
    reply_list = [b"\x00", b"\x01"]
        
    simul_system_manager = SimulSystemManager()
    packet = b"The crow has flown away:\nswaying in the evening sun,\naleafless tree."
    window_ack_manager = WindowAckModeManager(
        simul_system_manager, FRAGMENT_FORMAT, #fragment.fp,
        full_packet=packet, rule_id=0, dtag=0, window_size=7, fragment_size=4)

    def send_callback():
        #global window_ack_manager, simul_system_manager
        if len(reply_list) > 0:
            print("REPLY")
            reply_packet = reply_list.pop(0)
            simul_system_manager.add_event(1, window_ack_manager.event_packet, (reply_packet,))
    simul_system_manager.send_callback = send_callback # XXX
    
    simul_system_manager.add_event(0, window_ack_manager.start, ())
    simul_system_manager.run()

def test_window_ack_manager(args):
    system = RealTimeSystemManager((args.address, args.port),
                                   args.listen_port, args.time_scale)
    packet = ( b"The crow has flown away: "
              +b"- swaying in the evening sun, "
              +b"- a leafless tree.")
    window_ack_manager = WindowAckModeManager(
        system, FRAGMENT_FORMAT, #fragment.fp,
        full_packet=packet, rule_id=0, dtag=0, window_size=1, fragment_size=4)
    system.set_receive_packet_callback(window_ack_manager.event_packet)
    if args.inject:
        inject_receive_list = ([None]*12 + [b"\x00\xfe"] + [None]*20
                               + [b"\x01\xfe"])
        system.set_inject_receive_list(inject_receive_list)
    system.add_event(0, window_ack_manager.start, ())
    system.run()

#---------------------------------------------------------------------------
# POST packet processing

def process_packet(frag_manager, json_request):
    '''
    Processes one packet, in base64 in json_request["data"]
    Returns the packet that should be sent back as a json structure, with 
    at least {"data": <base 64 of packet>, ""}
    '''
    post_request = json.loads(json_request)

    if "data" in post_request:
        raw_packet = binascii.a2b_base64(post_request["data"])
        print(">>>PACKET:", bytes_to_hex(raw_packet))
        raw_reply_packet = frag_manager.event_packet(raw_packet)
    else:
        # This is a join
        print(">>>>JOIN")
        raw_reply_packet = b""

    print("<<<REPLY:", bytes_to_hex(raw_reply_packet))

    json_response = {
        "fport": 2,
        "data": binascii.b2a_base64(raw_reply_packet).decode("ascii")
    }
    return json_response

#---------------------------------------------------------------------------
# Bottle version
# -> bottle is simpler (one file), problem is for scheduling timers
# threading is probably needed

@post('/')
def device_packet_handler():
    global frag_manager
    print("--- received data")
    # https://stackoverflow.com/questions/14988887/reading-post-body-with-bottle-py
    response.set_header('Content-Type', 'application/json')
    raw_request = request.body.read()
    json_response = process_packet(frag_manager, raw_request)
    raw_response = json.dumps(json_response)
    return raw_response

#bottle.run(host='localhost', port=3112, debug=True)

#---------------------------------------------------------------------------
# Tornado version

# https://gist.github.com/cjgiridhar/3274687
def run_tornado(args):
    global frag_manager
    version = "magicarpe" if args.bis else "green"
    frag_manager = FragmentationManager(version)
    
    class Alive(tornado.web.RequestHandler):
        def get(self):
            self.write("server is alive")
    
    class PostHandler(tornado.web.RequestHandler):
        def post(self):
            raw_request = self.request.body
            json_request = raw_request.decode("ascii")
            json_response = process_packet(frag_manager, json_request)
            raw_response = json.dumps(json_response)
            self.write(raw_response)
    
    application = tornado.web.Application([
        (r"/alive", Alive),
        (r"/", PostHandler)
    ])

    application.listen(args.port, address=args.address)
    tornado.ioloop.IOLoop.instance().start()

#---------------------------------------------------------------------------

def cmd_run_server(args):
    global frag_manager
    version = "magicarpe" if args.bis else "green"
    if not args.tornado:
        frag_manager = FragmentationManager(version)        
        bottle.run(host=args.address, port=args.port, debug=args.debug)
    else:
        run_tornado(args)

#---------------------------------------------------------------------------

def cmd_post(args):
    # http://docs.python-requests.org/en/master/user/quickstart/#make-a-request
    raw_packet = b"hello-from-python"
    packet_b64 = binascii.b2a_base64(raw_packet).decode("ascii")
    s = json.dumps({"data":packet_b64, "fport":2})
    r = requests.post("http://{}:{}".format(args.address, args.port), data = s)
    print(r.text)

#---------------------------------------------------------------------------

def cmd_simple(args):
    # http://docs.python-requests.org/en/master/user/quickstart/#make-a-request
    if args.step == 0:   raw_packet = b"\x00\x00"
    elif args.step == 1: raw_packet = b"\x00\x01"
    elif args.step == 2: raw_packet = b"\x01\x01"
    elif args.step == 3: raw_packet = b"\x00\x01"
    elif args.step == 4: raw_packet = b"\x01\x01"
    else: raise ValueError("unmanaged step", args.step)

    packet_b64 = binascii.b2a_base64(raw_packet).decode("ascii")
    s = json.dumps({"data":packet_b64, "fport":2})
    r = requests.post("http://{}:{}".format(args.address, args.port), data = s)
    json_reply = json.loads(r.text)
    if "data" in json_reply:
        packet = binascii.a2b_base64(json_reply["data"]).decode("ascii")
        packet
    else: print("reply:", r.text)

#---------------------------------------------------------------------------

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command")

parser_server = subparsers.add_parser("server", help="run as POST server")
parser_server.add_argument("--address", default="0.0.0.0")
parser_server.add_argument("--port", default=3112)
parser_server.add_argument("--debug", default=False, action="store_true")
parser_server.add_argument("--bis", default=False, action="store_true")
parser_server.add_argument("--tornado", default=False, action="store_true")

parser_post = subparsers.add_parser("post", help="post a message")
parser_post.add_argument("--port", default=3112)
parser_post.add_argument("--address", default="localhost") 

parser_simple = subparsers.add_parser("simple", help="send one step of simple fragmentation")
parser_simple.add_argument("--port", default=3112)
parser_simple.add_argument("--step", type=int, default=0)
parser_simple.add_argument("--address", default="localhost") 

parser_test_window_ack = subparsers.add_parser("test-win-ack", help="test window ack manager")

parser_test_emul = subparsers.add_parser("test-emul")
parser_test_emul.add_argument("--address", default="localhost")
parser_test_emul.add_argument("--port", type=int, default=9999, help="destination port")
parser_test_emul.add_argument("--listen-port", type=int, default=9999)

parser_test_udp_window_ack = subparsers.add_parser(
    "udp-win-ack", help="test window ack manager")
parser_test_udp_window_ack.add_argument("--address", default="localhost")
parser_test_udp_window_ack.add_argument(
    "--port", type=int, default=9999, help="destination port")
parser_test_udp_window_ack.add_argument("--data", type=int, default=9999)
parser_test_udp_window_ack.add_argument("--listen-port", type=int, default=9999)
parser_test_udp_window_ack.add_argument(
    "--inject", default=False, action="store_true")
parser_test_udp_window_ack.add_argument(
    "--time-scale", default=1, type=float) # not working

args = parser.parse_args()

if args.command == "server":
    cmd_run_server(args)
elif args.command == "post":
    cmd_post(args)
elif args.command == "simple":
    cmd_simple(args)
elif args.command == "test-win-ack":
    test_window_ack_manager_internal()
elif args.command == "udp-win-ack":
    test_window_ack_manager(args)    
elif args.command == "test-emul":
    test_real_time_system_manager(args)
else: raise ValueError("bad command name", args.command)
    
#---------------------------------------------------------------------------
