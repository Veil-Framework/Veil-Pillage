"""

Module to detect Powershell installation on a host or host list.


Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Powershell Installation Detection"
        self.description = "Detects if Powershell is installed on a host or host list."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method" : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"]}
        
    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:
            
            # reg.exe command to detect if powershell is installed
            command = "reg query HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1 /v Install"
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            if result.startswith("error:"):
                self.output += "[!] Error '"+result+"' in detecting powershell using creds '"+username+":"+password+"' on : " + target + "\n" 
            elif result == "":
                self.output += "[!] No result file, detect PowerShell failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "0x1" in result:
                self.output += "[*] PowerShell detected using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "0x0" in result:
                self.output += "[*] PowerShell not detected using creds '"+username+":"+password+"' on : " + target + "\n"
            else:
                print "result:",result
                self.output += "[!] Error in detecting PowerShell using creds '"+username+":"+password+"' on : " + target + "\n"
