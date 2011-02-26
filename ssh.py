#!/usr/bin/env python

import base64
import socket
import sys
from optparse import OptionParser

import libssh2

class FPClient:
    def __init__(self, hostname, port=22):
        self.hostname = hostname
        self.port = port
        self.get_fingerprint()

    def get_fingerprint(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(20)
            self.sock.connect((self.hostname, self.port))
            self.sock.setblocking(1)

            self.session = libssh2.Session()
            self.session.startup(self.sock)

            hash = self.session.hostkey_hash(2) # 2=SHA1, 1=MD5
            self.fingerprint = base64.b16encode(hash)

            self.session.close()
            self.sock.close()

        except Exception, e:
            self.fingerprint = -1
            return

if __name__ == '__main__' :
    parser = OptionParser()
    parser.add_option("-p", "--print-fingerprint", action="store", dest="print_host",
                      default=None, help="print host's fingerprint")
    (options, args) = parser.parse_args()

    if options.print_host == None:
        print "nothing to do"
        sys.exit(0)

    host_str = options.print_host.split(":")
    host = host_str[0]
    port = 22
    
    if len(host_str) > 1:
        port = host_str[1]

    fpclient = FPClient(host, int(port))
    print fpclient.fingerprint
