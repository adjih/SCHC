#! /usr/bin/env python3
#---------------------------------------------------------------------------

import logging
import threading
import argparse
import requests

import json
import base64, binascii
import struct

import bottle # pip install bottle || wget https://bottlepy.org/bottle.py
from bottle import post, request, response

try:
    import tornado.ioloop
    import tornado.web
    with_tornado = True
except:
    print("cannot import tornado")
    with_tornado = False

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
    def __init__(self, version="magicarpe"):
        self.nb_bit_bitmap = 1
        self.max_fcn_per_window = self.nb_bit_bitmap - 1 # included
        
        self.window = 0
        self.fcn = self.max_fcn_per_window # protocol FCN
        self.fragment_index = 0 #
        self.content = None
        self.state = "init"
        self.version = version

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
        print("fragment window={} fcn={} current_frag_index={}".format(self.window, self.fcn, self.fragment_index))
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

#---------------------------------------------------------------------------
# POST packet I/O

def process_packet(frag_manager, json_request):
    post_request = json.loads(json_request)

    if "data" in post_request:
        raw_packet = binascii.a2b_base64(post_request["data"])
        print(">>>PACKET:", bytes_to_hex(raw_packet))
        raw_reply_packet = frag_manager.event_packet(raw_packet)
    else:
        # This is a join
        print(">>>>JOIN")
        raw_reply_packet = b""

    #raw_reply_packet = b"\x00\x00TOBE"
    print("<<<REPLY:", bytes_to_hex(raw_reply_packet))

    json_response = {
        "fport": 2,
        "data": binascii.b2a_base64(raw_reply_packet).decode("ascii")
    }
    return json_response

#---------------------------------------------------------------------------
# Bottle version

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

args = parser.parse_args()

if args.command == "server":
    cmd_run_server(args)
elif args.command == "post":
    cmd_post(args)
elif args.command == "simple":
    cmd_simple(args)
else: raise ValueError("bad command name", args.command)
    
#---------------------------------------------------------------------------
