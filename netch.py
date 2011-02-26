#!/usr/bin/env python

import base64
import errno
import os
import shlex
import signal
import socket
import subprocess
import sys
import syslog
import time
from optparse import OptionParser
from syslog import LOG_ERR, LOG_WARNING, LOG_INFO

import libssh2
import pylibconfig


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

class Netch():
    def __init__(self, options):
        self.options = options
        self.syslog = False
        self.online = False

    def log(self, msg, priority):
        if self.syslog and (self.log_info or priority != LOG_INFO):
            syslog.syslog(priority, msg)
        else:
            if priority == LOG_ERR:
                prefix = "error: "
                out = sys.stderr
            elif priority == LOG_WARNING:
                prefix = "warning: "
                out = sys.stderr
            elif priority == LOG_INFO:
                prefix = "info: "
                out = sys.stdout
                
            if self.log_info or priority != LOG_INFO:
                print >> out, prefix + msg

    def parse_config_file(self, filename):
        """ Parses config file """
        self.config = {}
        cfg = pylibconfig.Config()
        cfg.readFile(filename)

        # log to syslog?
        sv, svValid = cfg.value("syslog")
        if svValid and sv.lower() == "true":
            self.config['syslog'] = True
            syslog.openlog("netch", syslog.LOG_PID, syslog.LOG_DAEMON)
        else:
            self.config['syslog'] = False

        # log info?
        info, infoValid = cfg.value("log_info")
        if infoValid and info.lower() == "true":
            self.log_info = True
        else:
            self.log_info = False

        # load hooks
        for hook in ['online_hook', 'offline_hook']:
            self.config[hook] = []
            for hkey in cfg.children(hook):
                value, valid = cfg.value(hkey)
                if valid:
                    self.config[hook].append(os.path.expanduser(value))


        for stmt in ['host_delay', 'delay', 'delay_factor', 'delay_max']:
            value, valid = cfg.value(stmt)
            if not valid:
                print >> sys.stderr, "error: self.config file missing '%s' statement" % stmt
                sys.exit(1)

            self.config[stmt] = float(value)

        self.config['fingerprints'] = []
        for hostkey in cfg.children('fingerprints'):
            host, hostValid = cfg.value(hostkey+".host")
            port, portValid = cfg.value(hostkey+".port")
            fp, fpValid = cfg.value(hostkey+".fingerprint")

            if not hostValid:
                self.log("error parsing host", LOG_ERR)
                continue

            if not fpValid:
                self.log("error parsing fingerprint", LOG_ERR)
                continue

            if not portValid:
                port = 22

            self.config['fingerprints'].append((host, int(port), fp))
            
    def reload_config(self):
        self.parse_config_file(os.path.expanduser(self.options.config_file))
        self.current_delay = self.config["delay"]
        
    def handle_sigusr2(self, signum, frame):
        """ Reload config file on SIGUSR2 """
        self.reload_config()

    def run(self):
        self.reload_config()

        while True:
            for (host, port, fp) in self.config['fingerprints']:
                # if we're online, only verify we're onlune using the host we found out with
                if self.online != False:
                    ohost, oport = self.online
                    if host != ohost or port != oport:
                        continue

                fpclient = FPClient(host, port)
                if fpclient.fingerprint == -1:
                    self.log("unable to connect to %s:%s" % (host,port), LOG_INFO)
                    self.connection_down()
                    continue
                elif fpclient.fingerprint != fp:
                    self.log("received invalid fingerprint from %s:%s" % (host,port), LOG_WARNING)
                    continue
                elif fpclient.fingerprint == fp:
                    self.log("connected to %s:%s" % (host,port), LOG_INFO)
                    self.connection_up(host, port)

                time.sleep(self.config["host_delay"])

            delay = self.next_delay()
            self.log("sleeping for %s seconds " % delay, LOG_INFO)
            time.sleep(delay)

    def connection_up(self, host, port):
        self.current_delay = self.config["delay_max"]
        self.online = (host, port)
        for hook in self.config["online_hook"]:
            self.run_hook(hook)

    def connection_down(self):
        self.current_delay = self.config["delay"]
        self.online = False
        for hook in self.config["offline_hook"]:
            self.run_hook(hook)

    def run_hook(self, command):
        args = ["/bin/sh", "-c"]
        args.extend(shlex.split('"'+command+'"'))
        ret = subprocess.call(args)
        if ret != 0:
            self.log("hook '%s' returned with non-zero exit code %s" % (command,ret), LOG_ERR)

    def next_delay(self):
        """ Returns the next connection check delay """
        # immediately return the current delay if we're already at the max
        if self.current_delay == self.config["delay_max"]:
            return self.current_delay

        # increase delay by delay_factor
        delay = self.current_delay * self.config["delay_factor"]
        if delay <= config["delay_max"]:
            self.current_delay = delay
        else:
            self.current_delay = self.config["delay_max"]
            
        return self.current_delay

if __name__ == '__main__' :
    parser = OptionParser()
    parser.add_option("-p", "--print-fingerprint", action="store", dest="host",
                      default=None, help="print HOST's fingerprint and exit (host:port format)")
    parser.add_option("-c", "--config", action="store", dest="config_file",
                      default="~/.config/netch/config",
                      help="set config file (default: ~/.config/netch/config)")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      default=False, help="be verbose")
    (options, args) = parser.parse_args()

    #print host's fingerprint and exit?
    if options.host != None:
        host_str = options.host.split(":")
        host = host_str[0]
        port = 22
    
        if len(host_str) > 1:
            port = host_str[1]

        fpclient = FPClient(host, int(port))
        print fpclient.fingerprint

    netch = Netch(options)
    signal.signal(signal.SIGUSR2, netch.handle_sigusr2)
    netch.run()
