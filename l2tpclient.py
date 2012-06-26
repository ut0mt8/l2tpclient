#!/usr/bin/python

import os, socket, select, signal, errno, pty, tty, termios, fcntl, sys, time, binascii, struct, md5

# some config
DEBUG    = False
HOSTNAME = 'hostname'
VENDOR   = 'pyl2tp'
LNSHOST  = 'some.lns.com'
LNSPORT  = 1701
SECRET   = 'asecret'
USERNAME = 'user@realm'
TIMEOUT  = 60


# utilities function
def str2bin(s):
    return str(s) if s<=1 else str2bin(s>>1) + str(s&1)

def int2bin(s,size):
    a = str2bin(s)
    while len(a) < size:
        a = '0'+a
    return a

def set_non_blocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


# our main class
class L2tpClient(object):

    def __init__(self):
        self.debug = DEBUG
        self.host = LNSHOST
        self.port = LNSPORT
        self.peer_secret = SECRET
        self.ns = 0
        self.nr = 0
        self.tunnel_id = 0
        self.session_id = 0
        self.last_sent_packet_type = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect((self.host, self.port))
        self.pppd_fd = None


    # parse l2tp packet and act accordingly
    def parse_resp(self,buf):

        header_offset = 2
        avp_offset = 8
        nr = 0
        ns = 0

        # read the header
        (cflag,) = struct.unpack_from('!H', buf)

        cflag_bin = int2bin(cflag,16)
        ptype = cflag_bin[0]
        blen = cflag_bin[1]
        sbit = cflag_bin[4]
        obit = cflag_bin[6]
        pbit = cflag_bin[7]
        ver  = cflag_bin[12:16]

        if self.debug:
            print "<- l2tp packet dump"
            print "<-: l2tp cflag bits : %s|%s|%s|%s|%s|%s" % (ptype, blen, sbit, obit, pbit, ver)

        if ver != '0010': #
            print '!! Not an valid l2tp packet : discarding'
            return None

        if blen == '1':
            (plen,) = struct.unpack_from('!H', buf, offset=header_offset)
            if self.debug:
                print "<-: l2tp length : %d" % plen
            header_offset += 2

        (tid, sid) = struct.unpack_from('!HH', buf, offset=header_offset)
        if self.debug:
            print "<-: l2tp tunnel_id : %d, session_id : %d" % (tid, sid)
        header_offset += 4

        if sbit == '1':
            (ns, nr) = struct.unpack_from('!HH', buf, offset=header_offset)
            if self.debug:
                print "<-: l2tp ns : %d, nr : %d" % (ns, nr)
            header_offset += 4
            avp_offset += 4

        if obit == '1':
            (offset_size, offset_pad) = struct.unpack_from('!HH', buf, offset=header_offset)
            if self.debug:
                print "<-: l2tp offset_size : %d, offset_pad : %d" % (offset_size, offset_pad)
            header_offset += 4
            avp_offset += 4

        if ptype == '0': # data packet
            # write to pppd
            data = buf[header_offset:]
            try:
                async_buf = self.pppd_sync_to_async(data)
                pty._writen(self.pppd_fd, async_buf)
            except OSError, se:
                if se.args[0] not in (errno.EAGAIN, errno.EINTR):
                    raise

        elif ptype == '1': # control packet

            # test if we have avp pair
            if plen > 12 :

                # we should have a control msg, a tunnel id
                avp_control_msg = 0
                avp_tunnel_id = 0
                avp_challenge = ''

                # if not a ZLB increment nr of the next packet
                self.nr = ns + 1

                # parse avp
                while avp_offset < plen:
                    (avp_flag_len, avp_vendor_id, avp_type) = struct.unpack_from('!HHH', buf, offset=avp_offset)
                    avp_flag_len_bin = int2bin(avp_flag_len,16)
                    avp_mbit = avp_flag_len_bin[0]
                    avp_hbit = avp_flag_len_bin[1]
                    avp_len = int(avp_flag_len_bin[6:16],2)

                    # parse avp value
                    avp_value_offset = 6
                    avp_values = ''
                    while avp_value_offset < avp_len:
                        avp_value = buf[avp_offset+avp_value_offset:avp_offset+avp_value_offset+1]
                        avp_values += avp_value
                        avp_value_offset += 1

                    avp_values_hex = binascii.hexlify(avp_values)
                    avp_offset += avp_len

                    if self.debug:
                        print "<<-"
                        print "<: avp offset : %d" % avp_offset
                        print "<: avp flag bits : %s|%s" % (avp_mbit, avp_hbit)
                        print "<: avp length : %d" % avp_len
                        print "<: avp type : %d" % avp_type
                        print "<: avp values : %s" % avp_values_hex

                    # parse avp_type
                    if avp_type == 0: # control message
                        (avp_control_msg,) = struct.unpack('!H',avp_values)
                        if self.debug:
                            print "<< avp control message : %d" % avp_control_msg
                    elif avp_type == 1: # result code    
                        (avp_result_code,) = struct.unpack_from('!H',avp_values)
                        if self.debug:
                            print "<< avp result code : %d" % avp_result_code
                    elif avp_type == 2: # protocol version
                        (avp_protocol_version, avp_protocol_revision) = struct.unpack('!BB',avp_values)
                        if self.debug:
                            print "<< avp protocol version : %d, revision %d" % (avp_protocol_version, avp_protocol_revision)
                    elif avp_type == 3: # framing capabilities
                        (avp_framing_cap,) = struct.unpack_from('!B',avp_values,offset=3)
                        avp_framing_cap_bin = int2bin(avp_framing_cap,8)
                        avp_framing_async = avp_framing_cap_bin[6]
                        avp_framing_sync = avp_framing_cap_bin[7]
                        if self.debug:
                            print "<< avp framing capabilities, async : %s, sync %s" % (avp_framing_async, avp_framing_sync)
                    elif avp_type == 4: # bearer capabilities
                        (avp_bearer_cap,) = struct.unpack_from('!B',avp_values,offset=3)
                        avp_bearer_cap_bin = int2bin(avp_bearer_cap,8)
                        avp_bearer_analog = avp_bearer_cap_bin[6]
                        avp_bearer_digital = avp_bearer_cap_bin[7]
                        if self.debug:
                            print "<< avp bearer capabilities, analog : %s, digital %s" % (avp_bearer_analog, avp_bearer_digital)
                    elif avp_type == 6: # firmware revision
                        (avp_firmware_rev,) = struct.unpack('!H',avp_values)
                        if self.debug:
                            print "<< avp firmware revision : %d"  % avp_firmware_rev
                    elif avp_type == 7: # host name
                        avp_hostname = avp_values[:]
                        if self.debug:
                            print "<< avp hostname : %s"  % avp_hostname
                    elif avp_type == 8: # vendor name
                        avp_vendorname = avp_values[:]
                        if self.debug:
                            print "<< avp vendorname : %s"  % avp_vendorname
                    elif avp_type == 9: # assigned tunnel id
                        (avp_tunnel_id,) = struct.unpack('!H',avp_values)
                        self.tunnel_id = avp_tunnel_id
                        if self.debug:
                            print "<< avp tunnel id : %d"  % avp_tunnel_id
                    elif avp_type == 10: # receive window size
                        (avp_receive_wsize,) = struct.unpack('!H',avp_values)
                        if self.debug:
                            print "<< avp receive windows size : %d"  % avp_receive_wsize
                    elif avp_type == 11: # challenge
                        avp_challenge = avp_values[:]
                        if self.debug:
                            print "<< avp challenge : %s"  % binascii.hexlify(avp_challenge)
                    elif avp_type == 14: # assigned session
                        (avp_session,) = struct.unpack('!H',avp_values)
                        self.session_id = avp_session
                        if self.debug:
                            print "<< avp assigned session : %d"  % avp_session
                    else:
                        if self.debug:
                            print "<! avp %d not currently supported" % avp_type

                # control message
                if avp_control_msg == 1: # SCCRQ
                    print "< SCCRQ Control Message"
                elif avp_control_msg == 2: # SCCRP    
                    print "< SCCRP Control Message"
                    # make and send the SCCCN, with response to the challenge if applicable
                    challenge_resp = ''
                    if avp_challenge != '':
                        challenge_resp = self.make_challenge_response('03',avp_challenge)
                    data = self.make_scccn(challenge_resp=challenge_resp)
                    print "> sending SCCCN"
                    self.send_packet(data)
                    self.ns += 1
                    self.last_sent_packet_type = 3
                elif avp_control_msg == 3: # SCCRN    
                    print "< SCCRN Control Message"
                elif avp_control_msg == 4: # StopCCN   
                    print "< StopCCN Control Message"
                    print "Exiting..."
                    exit(1)
                elif avp_control_msg == 6: # Hello
                    print "< Hello Control Message"
                    data = self.make_zlb()
                    print "> sending ZLB"
                    self.send_packet(data)
                elif avp_control_msg == 10: # ICRQ
                    print "< ICRQ Control Message"
                elif avp_control_msg == 11: # ICRP
                    print "< ICRP Control Message"
                    # make and send the ICCN
                    data = self.make_iccn()
                    print "> sending ICCN"
                    self.send_packet(data)
                    self.ns += 1
                    self.last_sent_packet_type = 12
                elif avp_control_msg == 12: # ICCN
                    print "< ICCN Control Message"
                elif avp_control_msg == 14: # CDN 
                    print "<  CDN Control Message"
                    print "Exiting..."
                    exit(1)
                else: 
                    print "<! Unsupported Control Message %d" % avp_control_msg

            else:
                print "< ZLB Message"
                ack_ns = nr
                if ack_ns ==  self.ns: # ack packet
                    if self.last_sent_packet_type == 1: # SCCRQ
                        print "< Ack SCCRQ"
                    elif self.last_sent_packet_type == 2: # SCCRP
                        print "< Ack SCCRP"
                    elif self.last_sent_packet_type == 3: # SCCCN
                        print "< Ack SCCCN"
                        # OK we have an SCCCN ack, so send the ICRQ
                        data = self.make_icrq()
                        print "> sending IRCQ"
                        self.send_packet(data)
                        self.ns += 1
                        self.last_sent_packet_type = 10
                    elif self.last_sent_packet_type == 10: # ICRQ
                        print "< Ack ICRQ"
                    elif self.last_sent_packet_type == 11: # ICRP
                        print "< Ack ICRP"
                    elif self.last_sent_packet_type == 12: # ICCN
                        print "< Ack ICCN"
                        self.run_pppd()
                    else:
                        print "<! Ack Packet Type %d" % last_sent_packet_type


    def make_header (self,ptype='1',blen='1',sbit='1',obit='0',pbit='0',ver='0010',plen=12):
        # contruct l2tp header
        cflag= int(ptype+blen+'00'+sbit+'0'+obit+pbit+'0000'+ver,2)
        header_data = struct.pack('!HHHHHH',cflag,plen,self.tunnel_id,self.session_id,self.ns,self.nr)
        return header_data


    def make_avp (self,attr_type,avp_mbit='1',avp_hbit='0',avp_len=8,avp_vid=0,avp_raw_data='',**kwargs):
        # construct AVP pair
        avp_flag = int(avp_mbit+avp_hbit+'000000',2)
        avp_data = struct.pack('!BBH', avp_flag, avp_len, avp_vid) 
        avp_data += struct.pack('!H', attr_type)
        for key in sorted(kwargs.iterkeys()):
            avp_data += struct.pack('!H',kwargs[key])
        if avp_raw_data != '':
            avp_data += avp_raw_data
        return avp_data


    def make_zlb (self):
        # construct l2tp packet
        header_data = self.make_header(plen=12)
        return header_data


    def make_sccrq (self):
        # make avp
        avp_data = ''
        # Start_Control_Request
        avp_data += self.make_avp(attr_type=0, attr_value=1)
        # Protocol Version
        avp_data += self.make_avp(attr_type=2, attr_value=256)
        # Framing Capabilities
        avp_data += self.make_avp(attr_type=3, avp_len=10, attr_value1=0, attr_value2=3)
        # Bearer Capabilities
        avp_data += self.make_avp(attr_type=4, avp_len=10, attr_value1=0, attr_value2=0)
        # Firmware Revision
        avp_data += self.make_avp(attr_type=6, attr_value=1680)
        # Host Name
        avp_data += self.make_avp(attr_type=7, avp_len=6+len(HOSTNAME), avp_raw_data=binascii.a2b_qp(HOSTNAME))
        # Vendor Name
        avp_data += self.make_avp(attr_type=8, avp_len=6+len(VENDOR), avp_raw_data=binascii.a2b_qp(VENDOR))
        # Assigned Tunnel ID
        avp_data += self.make_avp(attr_type=9, attr_value=64773)
        # Receive Window Size
        avp_data += self.make_avp(attr_type=10, attr_value=4)

        # construct l2tp packet
        header_data = self.make_header(plen=12+87)
        l2tp_data = header_data + avp_data
        return l2tp_data


    def make_scccn (self,challenge_resp=''):
        # make avp
        avp_data = ''
        # Start_Control_Connected
        avp_data += self.make_avp(attr_type=0, attr_value=3)
        # Challenge Response
        if challenge_resp != '':
            avp_data += self.make_avp(attr_type=13, avp_len=22, avp_raw_data=challenge_resp)

        # construct l2tp packet
        header_data = self.make_header(plen=12+30)
        l2tp_data = header_data + avp_data
        return l2tp_data


    def make_icrq (self):
        # make avp
        avp_data = ''
        # Incoming_Call_Request
        avp_data += self.make_avp(attr_type=0, attr_value=10)
        # Assigned Session FIXME need to be random
        avp_data += self.make_avp(attr_type=14, attr_value=39849)
        # Call Serial Number
        avp_data += self.make_avp(attr_type=15, avp_len=10, attr_value1=0, attr_value2=1)
        # Bearer Type
        avp_data += self.make_avp(attr_type=18, avp_len=10, attr_value1=0, attr_value2=0)

        # construct l2tp packet
        header_data = self.make_header(plen=12+36)
        l2tp_data = header_data + avp_data
        return l2tp_data


    def make_iccn (self):
        # make avp
        avp_data = ''
        # Incoming_Call_Connected
        avp_data += self.make_avp(attr_type=0, attr_value=12)
        # Connect Speed
        avp_data += self.make_avp(attr_type=24, avp_len=10, attr_value1=0, attr_value2=0)
        # Framing type
        avp_data += self.make_avp(attr_type=19, avp_len=10, attr_value1=0, attr_value2=1)
        # RxConnect Speed
        avp_data += self.make_avp(attr_type=38, avp_len=10, attr_value1=0, attr_value2=0)

        # construct l2tp packet
        header_data = self.make_header(plen=12+38)
        l2tp_data = header_data + avp_data
        return l2tp_data


    def make_data (self,data):
        header_data = self.make_header(ptype='0', plen=12+len(data))
        l2tp_data = header_data + data
        return l2tp_data


    def make_challenge_response(self,ptype,challenge):
        m = md5.new()
        m.update(binascii.unhexlify(ptype))
        m.update(self.peer_secret)
        m.update(challenge)
        challenge_resp = m.digest()
        if self.debug:
            print ">> avp challenge response : %s"  % binascii.hexlify(challenge_resp)
        return challenge_resp
    

    def send_packet (self,data):
        self.sock.sendall(data)
    

    def pppd_async_to_sync(self,frame):
        # convert pppd frame from async to sync for sending to the network
        # see RFC 1662
        PPP_FLAG=0x7e
        PPP_ESCAPE=0x7d
        PPP_TRANS=0x20

        # ppp_flag at the beginning/end of a frame ?
        fs0 = frame.startswith(chr(PPP_FLAG))
        fs1 = frame.endswith(chr(PPP_FLAG))
        if fs0 and fs1:
            frame = frame[1:-1]
        elif fs0:
            frame = frame[1:]
        elif fs1:
            frame = frame[:-1]

        if not fs0:
            print "!! Invalid ppp frame, FS flag not found at the beginning"
        if not fs1:
            print "!! Incomplete ppp frame, FS flag not found at the end"
        
        pos = 0
        buf = ''
        while pos < len(frame):
            c = frame[pos]
            if c == chr(PPP_ESCAPE):
                # read the next byte and escape it
                pos += 1
                c = frame[pos]
                c = chr(ord(c) ^ PPP_TRANS)
                buf += c
            else:
                buf += frame[pos]
            pos += 1

        return buf


    def pppd_sync_to_async(self,frame):
        # convert ppp frame from sync to async for writing to ppp daemon
        # see RFC 1662
        PPP_FLAG=0x7e
        PPP_ESCAPE=0x7d
        PPP_TRANS=0x20
        PPPINITFCS16=0xffff

        # fcs calculation stuff
        # see RFC 1662 Appendix C
        def mkfcstab():
            P = 0x8408
            def valiter():
                for b in range(256):
                    v = b
                    i = 8
                    while i:
                        v = (v >> 1) ^ P if v & 1 else v >> 1
                        i -= 1
                    yield v & 0xFFFF
            return tuple(valiter())

        def pppfcs16(fcs, bytelist):
            fcstab = mkfcstab()
            for b in bytelist:
                fcs = (fcs >> 8) ^ fcstab[(fcs ^ b) & 0xff]
            return fcs

        def fcs(frame):
            fcs = pppfcs16(PPPINITFCS16, (ord(c) for c in frame)) ^ 0xFFFF
            fcsb1 = chr(fcs & 0x00FF)
            fcsb2 = chr((fcs & 0xFF00) >> 8)
            return fcsb1+fcsb2

        # add the fcs
        frame += fcs(frame)

        buf = ''
        # FS flag at the beginning of the frame
        buf += chr(PPP_FLAG)

        pos = 0
        while pos < len(frame):
            c = frame[pos]
            if c < chr(PPP_TRANS) or c == chr(PPP_FLAG) or c == chr(PPP_ESCAPE) :
                # escape this byte
                c = chr(ord(c) ^ PPP_TRANS)
                buf += chr(PPP_ESCAPE)
                buf += c
            else:
                buf += c
            pos += 1

        # FS flag at the end the frame
        buf += chr(PPP_FLAG)

        return buf


    def run_pppd (self):

        args = ['pppd', 'passive', 'nodetach', 'noauth', 'debug',
                'name', USERNAME, 'file', '/etc/ppp/options.l2tpd.client' ]
        print ">> launching pppd : "+" ".join(args)

        (child_pid, self.pppd_fd) = pty.fork()

        if child_pid == 0: # child process
            try:
                os.execvp("pppd", args)
            except:
                print "!! Error launching pppd"
                exit(127)
        else:
            try:
                p = os.ttyname(self.pppd_fd)
                print ">> the terminal device associated is: %s" % p
                set_non_blocking(self.pppd_fd)
                
                # main loop
                while True:

                    read = []
                    inputs = [self.pppd_fd, self.sock]
                    try:
                        if self.debug:
                            print ': waiting for the next l2tp/pppd packet'
                        read, _, _ = select.select(inputs, [], [])
                    except select.error, se:
                        if se.args[0] not in (errno.EAGAIN, errno.EINTR):
                            raise
                        continue

                    # read from pppd
                    if self.pppd_fd in read:
                        try:
                            buf = os.read(self.pppd_fd, 10000)
                            if not buf: #EOF
                                break

                            if self.debug:
                                print ":- read from pppd : %s" % len(buf)

                            sync_buf = self.pppd_async_to_sync(buf)
                            if sync_buf != None:
                                # write an l2tp data frame
                                data = self.make_data(sync_buf)
                                if self.debug:
                                    print "> sending data packet"
                                self.send_packet(data)
                            
                        except OSError, se:
                            if se.args[0] not in (errno.EAGAIN, errno.EINTR):
                                raise

                    # read from network
                    elif self.sock in read:
                        if self.debug:
                            print ":- read from network"
                        try:
                            buf = self.sock.recv(2048)
                            if not buf: #EOF
                                break
                            # parse the l2tp frame
                            self.parse_resp(buf)
                            
                        except OSError, se:
                            if se.args[0] not in (errno.EAGAIN, errno.EINTR):
                                raise

            finally:
                os.kill(child_pid, signal.SIGTERM)
                os.waitpid(child_pid, 0)


    def initial_loop (self):
        while True:    
            # Send initial SCCRQ
            self.ns = 0
            data = self.make_sccrq()
            print "> sending SCCRQ"
            self.send_packet(data)
            self.ns += 1
            self.last_sent_packet_type = 1

            inputs = [self.sock]
            while inputs:
                if self.debug:
                    print ': waiting for the next l2tp packet'
                read, _, _ = select.select(inputs, [], [], TIMEOUT)
                if not read: # timeout
                    break
                if self.sock in read:
                    buf = self.sock.recv(2048)
                    self.parse_resp(buf)


if __name__ == '__main__':
    l = L2tpClient()
    l.initial_loop()
