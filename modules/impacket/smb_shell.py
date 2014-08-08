"""

Execute impacket's smb client shell on a client.

All cred to the the awesome Impacket project !
    https://code.google.com/p/impacket/


Module built by @harmj0y

"""

from lib import helpers
from lib import impacket_smbclient

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "SMB Shell"
        self.description = ("Execute Impacket's cmb client shell module to create "
                            "on a client.")

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # any relevant text to echo to the output file
        self.output = ""

    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]

        # see if we need to extract a domain from "domain\username"
        domain = ""
        if "/" in username:
            domain,username = username.split("/")

        for target in self.targets:

            print "\n\n [*] Type "+helpers.color("'exit'") + " to exit the shell\n"

            # TODO: handle hashes
            shell = impacket_smbclient.MiniImpacketShell(username=username, password=password, domain=domain, host=target)
            shell.cmdloop()

            self.output += "[*] Impacket smbclient.py shell run using creds '"+username+":"+password+"' on "+target+"\n"
