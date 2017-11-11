#! /usr/bin/env python3
#---------------------------------------------------------------------------

import threading
import argparse
import requests

import json
import base64, binascii
import struct

import bottle # pip install bottle || wget https://bottlepy.org/bottle.py
from bottle import post, request, response

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
            self.process_ack(raw_packet)
        else: raise ValueError("bad state", self.state)
            
        #return b"helLO2"

    def get_current_fragment(self):
        print("fragment:", self.window, self.fcn, self.fragment_index)
        header = struct.pack(b"!BB", self.window, self.fcn)
        return header + bytes(self.content[self.fragment_index].encode("ascii"))

    def process_ack(self, raw_packet):
        print("process_ack", repr(raw_packet))
        if len(raw_packet) != struct.calcsize("!BB"):
            print("XXX: bad ack size", len(raw_packet))
            return b"XXX:bad"
        window, bitmap = struct.unpack("!BB", raw_packet)
        print(window, bitmap)
        if window != self.window:
            print("warning: bad window number", window, self.window)
            return b"XXX:bad-window"
        if bitmap != 1: #XXX
            print("warning: incomplete bitmap", bitmap, self.bitmap)
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

@post('/')
def device_packet_handler():
    global frag_manager
    print("--- received data")
    # https://stackoverflow.com/questions/14988887/reading-post-body-with-bottle-py
    print("post request content:", request.body.read())
    response.set_header('Content-Type', 'application/json')
    request_raw_content = request.body.read()
    request_json = request_raw_content.decode("ascii")
    post_request = json.loads(request_json)

    if "data" in post_request:
        raw_packet = binascii.a2b_base64(post_request["data"])
        #print(">>>PACKET:", repr(raw_reply_packet))
        #XXX!! raw_reply_packet = frag_manager.event_packet(raw_packet)
    else:
        # This is a join
        print(">>>>JOIN")
        raw_reply_packet = b""

    raw_reply_packet = b"\x00\x00TOBE"
    print("<<<REPLY:", repr(raw_reply_packet))

    json_response = {
        "fport": 2,
        "data": binascii.b2a_base64(raw_reply_packet).decode("ascii")
    }
    
    json_response = json.dumps(json_response)
    return json_response

#bottle.run(host='localhost', port=3112, debug=True)

#---------------------------------------------------------------------------

def cmd_run_server(args):
    global frag_manager
    version = "magicarpe" if args.bis else "green"
    frag_manager = FragmentationManager(version)
    bottle.run(host="79.137.84.149", port=args.port, debug=args.debug)
    #bottle.run(host="0.0.0.0", port=args.port, debug=args.debug)

#---------------------------------------------------------------------------

def cmd_post(args):
    # http://docs.python-requests.org/en/master/user/quickstart/#make-a-request
    r = requests.post("http://localhost:{}".format(args.port), data = {"key":"value"})
    print(r.text)

#---------------------------------------------------------------------------

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command")

parser_server = subparsers.add_parser("server", help="run as POST server")
parser_server.add_argument("--port", default=3112)
parser_server.add_argument("--debug", default=False, action="store_true")
parser_server.add_argument("--bis", default=False, action="store_true")

parser_post = subparsers.add_parser("post")
parser_post.add_argument("--port", default=3112)


args = parser.parse_args()

if args.command == "server":
    cmd_run_server(args)
elif args.command == "post":
    cmd_post(args)
else: raise ValueError("bad command name", args.command)
    
#---------------------------------------------------------------------------
