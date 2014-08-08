"""

Module to 

Module built by @name

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Check something"
        self.description = "Does something something something"

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
        self.required_options = {"trigger_method" : ["wmis", "[wmis] or [winexe] for triggering"]}

        
    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]

        for target in self.targets:

            print " [*] Doing soemthing on %s" %(target)
            command = "something to do on the host"

            # ...
            result = command_methods.executeResult(target, username, password, command, self.required_options["trigger_method"][0])

            # check our output and write output/cleanup as appropriate
            if "something" in result:
                self.output += "action successful on " + target + "\n"
                # this needs to be tab-separated, check a module for examples
                self.cleanup += "cleanup command " + target + "\n"

        # finally return our putput and cleanup text
        return (self.output, self.cleanup)

