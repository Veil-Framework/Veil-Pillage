#!/usr/bin/python

"""
Small script to monitor for all STATUS_OBJECT_NAME_NOT_FOUND
NT status errors (0xC0000034) using tshark. 

All found .dll's from these packets are extracted out, displayed,
and optionally logged to a file.

This script should be used in conjunction with the persistence/registry/unc_dll
Veil-Pillage module to find .dll hijacking opportunities.

Concept from:
    http://carnal0wnage.attackresearch.com/2013/09/finding-executable-hijacking.html


Built by @harmj0y

"""

import time, pexpect, sys, re, datetime, os
import threading, ConfigParser, argparse
from impacket import smbserver


class ThreadedSMBServer(threading.Thread):
    """
    Threaded SMB server that can be spun up locally.

    Hosts the files in /tmp/shared/ as HOST\\SYSTEM\\
    """

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','SERVICE')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file','/tmp/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section("SYSTEM")
        smbConfig.set("SYSTEM",'comment','system share')
        smbConfig.set("SYSTEM",'read only','yes')
        smbConfig.set("SYSTEM",'share type','0')
        smbConfig.set("SYSTEM",'path',"/tmp/shared/")

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)

        # print '\n [*] setting up SMB server...'
        self.smb.processConfigFile()
        try:
            self.smb.serve_forever()
        except:
            pass

    def shutdown(self):
        # print '\n [*] killing SMB server...'
        self.smb.shutdown()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

        # make sure all the threads are killed
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except:
                    pass

def title():
    """
    Print the tool title, with version.
    """
    os.system('clear')
    print "========================================================================="
    print " DLL-Hijack Monitor"
    print '========================================================================='
    print ' [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework'
    print '========================================================================='


def validIP(IP):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', IP):
        return True
    else:
        return False


if __name__ == '__main__':

    # create our arugment parse groups and add whatever we need
    parser = argparse.ArgumentParser()
    group = parser.add_argument_group('General options')
    group.add_argument('-o', metavar="output.txt", nargs='?', help='Output file to write results to.')
    args = parser.parse_args()
    
    outFile = None
    if args.o:
        # if we have an output file, open and print a starting timestamp
        outFile = open(args.o, 'a')
        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y-%H:%M:%S')
        outFile.write("\n=========================================================================\n")
        outFile.write("Dll-Hijack Monitor started at: " + timestamp + "\n")
        outFile.write("=========================================================================\n")

    title()

    # tshark command to filter for the messages we need
    tsharkCMD = "tshark -f \"port 445\" -Y \"smb.nt_status==0xc0000034\""

    proc = pexpect.spawn(tsharkCMD, timeout=None)

    server = ThreadedSMBServer()
    server.start()

    print "\n [*] Potential host:dll's to hijack:\n"

    #continuously monitor the standard output
    while True:
        try:
            line = proc.readline()
            if ".dll" in line:
                ip = ""
                parts = line.split()

                for x in xrange(len(parts)):
                    if ip == "":
                        if validIP(parts[x]):
                            ip = parts[x]

                timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y-%H:%M:%S')

                for part in parts:
                    if part.endswith("dll"):
                        print " "+timestamp+"\t"+ip+" : "+part[1:]
                        if outFile:
                            outFile.write(timestamp+"\t"+ip+" : "+part[1:]+"\n")

        except KeyboardInterrupt:
            server.shutdown()
            if outFile:
                timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y-%H:%M:%S')
                outFile.write("=========================================================================\n")
                outFile.write("Dll-Hijack Monitor closed at: " + timestamp + "\n")
                outFile.write("=========================================================================\n\n")

            sys.exit("\nexiting... see ya!")

