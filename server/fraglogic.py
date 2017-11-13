#---------------------------------------------------------------------------

import warnings
import struct

import sys
sys.path.append("../../PLIDO-tanupoo")
import fragment
#import schc_fragment as fragment

#---------------------------------------------------------------------------

INTER_FRAGMENT_DELAY = 1.0 # seconds
WAIT_BITMAP_TIMEOUT = 5.0 # seconds

class WindowAckModeSender:
    """The fragmentation manager handles the logic of the fragment sending etc.
    """
    
    def __init__(self, system_manager, fragment_format, full_packet,
                 rule_id, dtag, window_size, fragment_size):
        self.system_manager = system_manager
        fragment.fp = fragment_format #XXX: hack
        self.fragment = fragment.fragment(
            srcbuf=full_packet, rule_id=rule_id, dtag=dtag,
            noack=False, window_size=window_size)
        #self.fragment = fragment.fragment(
        #    srcbuf=full_packet, dtag=dtag, rid=rule_id)
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

#---------------------------------------------------------------------------
