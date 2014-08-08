"""

Issues a command to disable the RDP service on a host.

Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Disable RDP"
        self.description = "Disables RDP on a host or host list."
        
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

        # user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method" : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"]}

    def run(self):

        # assume single set of credentials (take the first one)
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:

            # disable RDP command
            rdpCMD = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f"

            # execute the RDP enable command and get the result
            rdpResult = command_methods.executeResult(target, username, password, rdpCMD,triggerMethod)

            if rdpResult == "":
                self.output += "[!] No result file, RDP disable failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "The operation completed successfully" in rdpResult:
                self.output += "[*] RDP successfully disabled using creds '"+username+":"+password+"' on : " + target + "\n"
