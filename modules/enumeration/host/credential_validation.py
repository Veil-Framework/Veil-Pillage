"""

Module to validate a set of credentials against a host or host list.

Module built by @harmj0y

"""

from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Credential Validation"
        self.description = "Validates a set of credentials against a host or host list."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

    def run(self):

        for target in self.targets:
            for cred in self.creds:
                username, password = cred
                try:
                    result = smb.verifyLogin(target, username, password)
                    if result:
                        self.output += "[*] Credentials '%s:%s' valid for %s\n" %(username, password, target)
                    else:
                        self.output += "[!] Credentials '%s:%s' not valid for %s\n" %(username, password, target)
                except Exception as e:
                    # print "Exception:",e
                    self.output += "[!] Exception validating credentials %s:%s for %s\n" %(username, password, target)
        
