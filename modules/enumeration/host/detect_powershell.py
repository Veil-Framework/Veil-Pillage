"""

Module to detect a functional Powershell installation on a host or host list.


TODO: implement parts of https://github.com/DiabloHorn/DiabloHorn/blob/master/remote_appinitdlls/rapini.py
        for remote registry modifications? 

Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Powershell Detection"
        self.description = "Detects a functional Powershell installation on a host or host list."

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
            
            # reg_command = "reg query HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1 /v Install"
            # but we don't actually care usually if it's installed, just if it's functionality
            # so let's just invoke it yo'
            command = "powershell.exe -c \"$a=42;$a\""
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            if result.strip() == "42":
                self.output += "[*] Powershell detected as functional using creds '"+username+":"+password+"' on : " + target + "\n"
            else:
                self.output += "[!] Powershell not detected as functional using creds '"+username+":"+password+"' on : " + target + "\n"
