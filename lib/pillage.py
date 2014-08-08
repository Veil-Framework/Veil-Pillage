"""

The meat of the Veil-Pillage framework containing the controller logic.

"""

import sys, os, readline, datetime, select
import glob, commands, imp, pickle, time
from os.path import join, basename, splitext


########################################################################
#
# Check to make sure the common Veil-Framework settings file
# and other needed resources/dependencies exist.
#
# If anything is missing, reruns ./update.py to get everything 
# squared away.
#
########################################################################

# Try to import the common Veil-Framework settings.py file
# Lots of bounary/issue checking here, try to handle as
# many edge cases as we can...
if os.path.exists("/etc/veil/settings.py"):
    try:
        sys.path.append("/etc/veil/")
        import settings

        # check for a few updated values to see if we have an updated settings.py file
        try:
            settings.VEIL_PILLAGE_PATH
            # append veil-evasion's path to the parent path for later reference
            sys.path.append(settings.VEIL_EVASION_PATH)
        except AttributeError:
            os.system('clear')
            print '========================================================================='
            print ' New major Veil-Pillage version installed'
            print ' Re-running ./update.py'
            print '========================================================================='
            time.sleep(3)
            os.system('./update.py')

            # reload the settings import to refresh the values
            reload(settings)

    except ImportError:
        print "\n [!] ERROR: run ./config/update.py manually\n"
        sys.exit()

else:
    # if the settings file isn't found, try to run the update script
    os.system('clear')
    print '========================================================================='
    print ' Veil-Pillage First Run Detected... Initializing Script Setup...'
    print '========================================================================='
    # run the config if it hasn't been run
    print '\n [*] Executing ./update.py'
    os.system('./update.py')

    # check for the config again and error out if it can't be found.
    if os.path.exists("/etc/veil/settings.py"):
        try:
            sys.path.append("/etc/veil/")
            import settings
        except ImportError:
            print "\n [!] ERROR: run ./config/update.py manually\n"
            sys.exit()
    else:
        print "\n [!] ERROR: run ./config/update.py manually\n"
        sys.exit()

# check for the Impacket installation
try:
    from impacket import smbserver
    from impacket.smbconnection import *
except ImportError:
    print "\n"
    print "\n [!] Impacket not installed"
    print "\n [*] Executing ./update.py"
    time.sleep(2)
    os.system('./update.py')
    time.sleep(2)

# check for passing-the-hash (pth-wmis/pth-winexe)
out = commands.getoutput("pth-wmis")
if "not found" in out:
    print "\n"
    print "\n [!] passing-the-hash not installed"
    print '\n [*] Executing ./update.py'
    time.sleep(2)
    os.system('./update.py')
    time.sleep(2)


# Veil-Pillage specific imports from ./lib/
from lib import helpers
from lib import completers
from lib import messages
from lib import msfdatabase
from lib import command_methods
from lib import smb


# Main Pillage controller class
class Pillage:

    def __init__(self, args):

        self.modules = list()
        self.args = args

        # commands available in the main menu
        self.mainCommands = [   ("use"      , "use a specific module"),
                                ("list"     , "list available [modules, targets, creds]"),
                                ("set"      , "set [targets, creds]"),
                                ("setg"     , "set global module option"),
                                ("reset"    , "reset [targets, creds]"),
                                ("db"       , "interact with the MSF database"),
                                ("cleanup"  , "run a module cleanup script"),
                                ("exit"     , "exit Veil-Pillage")]

        # commands available in a module menu
        self.moduleCommands = [ ("run"  , "run the module"),
                                ("info" , "display this module's information"),
                                ("list" , "list currently set [targets, creds]"),
                                ("set"  , "set a specific option value"),
                                ("setg" , "set global module option"),
                                ("reset", "reset a specific option value"),
                                ("db"   , "interact with the MSF database"),
                                ("back" , "go to the main menu"),
                                ("exit" , "exit Veil-Pillage")]

        # options available to the "set" command
        self.setOptions = [  ("targets" , "Single IP, comma-separated IP set, or ip list file"),
                             ("creds"   , "password, LM:NTLM hash or credump file")]

        # MSF database inteartion options available to the "db" command
        self.dbOptions = [  ("connect"      , "Connect to the MSF database"),
                            ("list_creds"   , "List the credentials in the MSF database"),
                            ("add_creds"    , "Set credentials based to MSF database values"),
                            ("list_targets" , "List the hosts in the MSF database"),
                            ("add_targets"  , "Set hosts based to MSF database values"),
                            ("listeners"    , "List all Cobalt Strike listeners from the MSF database"),
                            ("use_listener" , "Use options from a particular Cobalt Strike listener")]

        # current running target/credential sets
        self.targets = []

        # nested list of [ [(domain/)username, pw/hash], ...]
        self.creds = []

        # load up all the available modules
        self.loadModules()

        # instantiate metasploit DB connection object and try to connect to it
        self.msfdatabase = msfdatabase.Database(args)
        self.msfdatabase.connect()

        # the currently executing module, for state restore
        self.currentModule = None

        # TODO:   
                # self.moduleMenu(self.currentModule)            
                # # then back to the main menu if we get an exit?
                # pillage.mainMenu()

        #
        # State restore stuff to restore self.creds, self.targets and self.modules
        #   self.modules retores the configured state of all modules last run
        #
        # if we have a manual restore file passed, run it without prompting
        if self.args.s:
            # if the restore file exists, open it up and unpickle it
            if os.path.exists(self.args.s):
                try:
                    f = open( self.args.s, "rb" )
                    (self.currentModule, self.currentModule, self.targets, self.creds, self.modules) = pickle.load(f)
                    # jump to the executing module if it was set
                    if self.currentModule: self.moduleMenu(self.currentModule)
                except IOError as e: 
                    print " [!] Error loading "+self.args.s+"\n"
                    time.sleep(3)
            else:
                print " [!] State file "+self.args.s+" doesn't exist\n"

        # if no manual file is passed, use "pillage.state" as the default
        else:
            # only perform this logic if pillage.state actually exists
            if os.path.exists("pillage.state"):
                # if args or settings say we shouldn't restore, skip it (or if we're cleaning output folders)
                if self.args.norestore or settings.PILLAGE_STATE_RESTORE.lower() == "false" or self.args.clean or self.args.cleanup:
                    print helpers.color(" [!] Skipping state restore...\n", warning=True)
                # otherwise restore/prompt for user interaction
                else:
                    sys.stdout.write(" [!] '"+helpers.color("pillage.state")+"' save state found. Load? [Y/n] > ")
                    sys.stdout.flush()
                    try:
                        f = open( "pillage.state", "rb" )
                        # 5 second timeout for a response, otherwise default to "yes"
                        i, o, e = select.select( [sys.stdin], [], [], 5 )
                        print ""
                        # if we get a response from the user, check if it's a 'yes' or default
                        if (i):
                            choice = sys.stdin.readline().strip()
                            # if we get a default or a Yes, restore the state
                            if len(choice) == 0 or choice.lower()[0] == "y":
                                # (self.targets, self.creds) = pickle.load(f)
                                (self.currentModule, self.targets, self.creds, self.modules) = pickle.load(f)
                                # jump to the executing module if it was set
                                if self.currentModule: self.moduleMenu(self.currentModule)
                        # if we don't get a response assume the default of "yes" for a state restore
                        else:
                            (self.currentModule, self.targets, self.creds, self.modules) = pickle.load(f)
                            # jump to the executing module if it was set
                            if self.currentModule: self.moduleMenu(self.currentModule)
                    except IOError as e: 
                        print " [!] Error loading pillage.state"+"\n"
                        time.sleep(3)

        # parse most passed arguments and set appropriate values
        self.parseArgs()



    ########################################################################
    #
    # Misc helper methods.
    #
    ########################################################################

    def parseArgs(self):
        """
        Parse most passed arguments that are passed into self.args,
        extract all options and set appropriate values.

        """

        # credential arguments - args.U, args.P, args.cF
        # self.args is of the form [ [(domain/)username, pw/hash], ...]
        # have to have both a user and password/hash specified
        # 
        # TODO: want to .extend() the creds or replace here?
        #
        if self.args.U and self.args.P:
            # append this cred set to the internal args object
            self.creds.extend( [[self.args.U, self.args.P]] )

        # if a credential file was passed, parse it and append it to
        # the internal self.creds objects
        if self.args.cF:
            # append this cred set to the internal args object
            self.creds.extend(self.parseCredfile(self.args.cF))

        # if "-t TARGET" or "-t TARGET1,TARGET2,..." is passed
        if self.args.t:
            for t in self.args.t.split(","):
                # append this target to the internal target list
                self.targets.append(t)

        # if a target list is passed
        if self.args.tL:
            # if we have a target file, try to parse it
            if os.path.exists(self.args.tL):
                # open the target file and parse the IPs/hosts
                f = open(self.args.tL)
                lines = f.readlines()
                f.close()
                # add all of these targets to the internal target list
                self.targets.extend([line.strip() for line in lines if line.strip() != ""])
            else:
                print helpers.color(" [!] Invalid target list passed: " + self.args.tL + "\n", warning=True)


    def parseCredfile(self, credfile):
        """
        Parse a credump-formatted or straight "user:password\nuser2:password2..." credential file.

        Returns a credential list of [[user, pw], [user2, pw2],...]
        """
        
        creds = []

        # make sure we have an existing file
        if os.path.exists(credfile):

            try:
                f = open(credfile)
                lines = f.readlines()
                f.close()
            except:
                print helpers.color(" [!] Error reading file '"+credfile+"'", warning=True)

            # parse each line in the cred file
            for line in lines:

                # make sure the line isn't empty
                if line != "":
                    if ":" in line:
                        # split the line up
                        parts = [x.strip() for x in line.split(":") if x != ""]

                        # check if we have "user:password" foramt
                        if len(parts) == 2:
                            creds.append([parts[0], parts[1]])
                        # check if we have "user:LM:NTLM" format
                        if len(parts) == 3:
                            creds.append([parts[0], parts[1] + ":" + parts[2]])
                        # check if we have a creddump file format
                        elif len(parts) == 4:
                            creds.append([parts[0], parts[2] + ":" + parts[3]])
                    
                    # check if we have a space-separated cred line
                    else:
                        parts = line.split()

                        # if we have "user cred" format, otherwise skip
                        if len(parts) == 2:
                            creds.append([parts[0], parts[1]])
        else:
            print helpers.color(" [!] Warning: file %s does not exist" %(credfile), warning=True)

        return creds


    def cleanup(self):
        """
        Close off any database connections, save off current state, etc.
        """

        # close down the database connection if it exists
        self.msfdatabase.close()

        # save off the current target/cred sets unless '--norestore' or the PILLAGE_STATE_RESTORE=false
        # options are set
        if not (self.args.norestore or settings.PILLAGE_STATE_RESTORE.lower() == "false"):
            pickle.dump( (self.currentModule, self.targets, self.creds, self.modules), open( "pillage.state", "wb" ) )
        

    def cleanOutputFolders(self):
        """
        Cleans out the output folders at PILLAGE_OUTPUT_PATH
        """
        
        # if --clean is passed, don't prompt - just clean and exit
        if self.args.clean:

            print "\n [*] Cleaning %s" %(settings.PILLAGE_OUTPUT_PATH)
            os.system('rm -rf %s/* 2>/dev/null' %(settings.PILLAGE_OUTPUT_PATH))
            print "\n [*] Folders cleaned\n"
            sys.exit()

        # prompt for confirmation if we're in the interactive menu        
        else:
            choice = raw_input("\n [>] Are you sure you want to clean the output folders folders? [y/N] ")

            if choice.lower() == "y":
                print "\n [*] Cleaning %s" %(settings.PILLAGE_OUTPUT_PATH)
                os.system('rm -rf %s/* 2>/dev/null' %(settings.PILLAGE_OUTPUT_PATH))
                print "\n [*] Folders cleaned\n"


    ########################################################################
    #
    # Methods for loading and interacting with/displaying usable modules.
    #
    ########################################################################

    def loadModules(self):
        """
        Crawl the module path and load up everything found.
        """

        # crawl down 5 levels in the module path and instantiate all the modules
        for x in xrange(1,5):    
            # builds out all the appropriate paths... trust me :)
            # to change the name of the module being loaded, change join(path.split("/")[-1:]) to  join(path.split("/")[2:])
            # but to allow for state preservation, we need to keep only the 'name' as
            # keeping "/" in the module names fucks up the pickle-loading >_<
            d = dict( (path[path.find("modules")+8:-3], imp.load_source( "/".join(path.split("/")[-1:])[:-3],path )  ) for path in glob.glob(join("./modules/" + "*/" * x,'[!_]*.py')) )
            
            # actually instantiate the modules
            for name in d.keys():

                module = d[name].Module()

                # if the module has "self.args", pass the main program args along
                # in case it wants to use them later
                if hasattr(module, "args"):
                    module.args = self.args

                self.modules.append( (name, module) )

        # sort the modules by name
        self.modules = sorted(self.modules, key=lambda x: (x[0]))


    def listModules(self):
        """
        Nicely prints out all loaded modules.
        """
        messages.title()
        print helpers.color(" [*] Available modules:\n")
        lastBase = None
        x = 1
        for (name, module) in self.modules:
            parts = name.split("/")
            if lastBase and parts[0] != lastBase:
                print ""
            lastBase = parts[0]
            print "\t%s)\t%s" % (x, '{0: <24}'.format(name))
            x += 1
        print ""


    ########################################################################
    #
    # Metasploit database methods - mostly just display
    #   heavily utilizes ./lib/msfdatabase.py for the acutal interaction
    #
    ########################################################################

    def listMSFTargets(self):
        """
        Lists the targets available from the internal MSF database object.
        """

        # grab the host list from the internal MSF database object
        targets = self.msfdatabase.getMSFHosts()

        if targets != "":
            print ""
            print " [*] Targets currently in the MSF database:\n"
            print " num  target"
            print " ---  ----"
            x = 1
            for target in targets:
                print " %s%s" % ('{0: <5}'.format(x), '{0: <17}'.format(target))
                x += 1
            print ""


    def listMSFCreds(self):
        """
        Lists the creds available from the internal MSF database object.
        """

        # grab the host list from the internal MSF database object
        creds = self.msfdatabase.getMSFCreds()

        if creds != "":
            print ""    
            print " [*] Creds currently in the MSF database:\n"
            print " num  host             port   user                pass"
            print " ---  ----             ----   ----                ----"
            x = 1
            for cred in creds:
                host,port,username,password = cred
                print " %s%s%s%s%s" % ('{0: <5}'.format(x), '{0: <17}'.format(host), '{0: <7}'.format(port), '{0: <20}'.format(username), password) 
                x += 1
            print ""


    def listCSListeners(self):
        """
        Lists the Cobalt Strike listeners available in the database.
        """

        # grab the host list from the internal MSF database object
        listeners = self.msfdatabase.getCSListeners()

        if listeners != "":
            print ""    
            print " [*] Active Cobalt Strike listeners:\n"
            print " num  name        payload                             lhost:lport"
            print " ---  ----        -------                             -----------"
            x = 1
            for listener in listeners:
                (name, payload, lhost, lport) = listener
                print " %s%s%s%s" % ('{0: <5}'.format(x), '{0: <12}'.format(name), '{0: <36}'.format(payload), lhost+":"+lport) 
                x += 1
            print ""


    def addMSFCreds(self, choice):
        """
        Query the MSF database for creds add the result # from the 
        database (via list creds) to internal self.creds.

        "choice" is a single numerical value or a comma/space separated list of choices
        """

        # grab the cred list from the internal MSF database object
        creds = self.msfdatabase.getMSFCreds()

        if creds != "":
            print "" 
            print " [*] Adding creds from the MSF database:\n"

            # split the choice list by commas and/or spaces
            choices = choice.strip().replace(",", " ").split()

            for c in choices:
                try:
                    cred = creds[int(c)-1]
                    print helpers.color("\t" + cred[2] + ":" + cred[3]) 
                    self.creds.append( [cred[2],cred[3]] )
                except Exception as e:
                    print helpers.color("\n [!] Invalid choice: " + str(c) + "\n", warning=True)

            print ""


    def addMSFTargets(self, choice):
        """
        Query the MSF database for targets add the result # from the 
        database (via list_targets) to internal self.hosts.

        "choice" is a single numerical value or a comma/space separated list of choices
        """

        # grab the host list from the internal MSF database object
        targets = self.msfdatabase.getMSFHosts()
        
        if targets != "":
            print "" 
            print " [*] Adding targets from the MSF database:\n"

            if not self.targets: self.targets = []

            # split the choice list by commas and/or spaces
            choices = choice.strip().replace(",", " ").split()

            for c in choices:
                try:
                    target = targets[int(c)-1]
                    print helpers.color("\t" + target) 
                    self.targets.append(target)
                except Exception as e:
                    print helpers.color("\n [!] Invalid choice: " + str(c) + "\n", warning=True)

            print ""

            # uniqify the targets we've added to ensure no duplicates
            self.targets = list(set(self.targets))

            # sort the IPs
            helpers.sortIPs(self.targets)


    def useCSListener(self, choice):
        """
        Query the MSF database for Cobalt Strike listeners, take the result # 
        from the database (via db listeners), extract the lhost/lport and
        other optoins, and set all these options globally.

        "choice" is a single numerical value or a comma/space separated list of choices
        """

        # grab the host list from the internal MSF database object
        listeners = self.msfdatabase.getCSListeners()

        if listeners != "":

            # grab the first choice element
            choice = choice.strip().replace(",", " ").split()[0]

            try:
                listener = listeners[int(choice)-1]
                (name, payload, lhost, lport) = listener

                print "\n [*] Setting options from Cobalt Strike listener:\n"

                print " name        payload                             lhost:lport"
                print " ----        -------                             -----------"
                print helpers.color(" %s%s%s" % ('{0: <12}'.format(name), '{0: <36}'.format(payload), lhost+":"+lport))

                # set lhost/lport globally
                self.setGlobalOptions( [ ["lhost", lhost], ["lport", lport] ])

                # try to extract some options from the payload
                if "tcp" in payload:
                    self.setGlobalOptions( [ ["stager", "rev_tcp"] ])
                elif "https" in payload:
                    self.setGlobalOptions( [ ["stager", "rev_https"] ])
                elif "http" in payload:
                    self.setGlobalOptions( [ ["stager", "rev_http"] ])

                # try to set msfpayload/msfoptions - do we really want this?
                # self.args.msfpayload = payload
                # self.args.msfoptions = "LHOST="+lhost+" LPORT="+lport

            except Exception as e:
                print helpers.color("\n [!] Invalid choice: " + str(choice), warning=True)

            print ""


    ########################################################################
    #
    # Methods for interacting with the underlying credential, target,
    # and global options.
    #
    ########################################################################

    def setGlobalOptions(self, options):
        """
        Iterate through all modules currectly loaded and set the passed
        options for each module.

        'options' format is [[option, value], [option2, value2], ...]
        """

        # if "options" is a string, turn it into a dictionary really quick
        if type(options) is str:
            options = [options]

        for (name, module) in self.modules:

            # if the module has required_options
            if hasattr(module, 'required_options'): 
                # and setModule() was passed options to set (usually by command line)
                if len(options) != 0:
                    # try to extract the option/value pairs, and print an error message
                    # if incorrectly formatted
                    for l in options:
                        try:
                            [option,value] = l
                            # if the passed option is a required_option
                            if option.lower() in module.required_options:
                                # set the value for that option in the module
                                module.required_options[option.lower()][0] = value
                        except:
                            print helpers.color(" [!] Incorrectly formatted option: '" + l[0]+"'", warning=True)
                            print helpers.color(" [*] Please use OPTION=VALUE format")
                            time.sleep(3)


    def setTargets(self, targets):
        """
        Set the internal targets to a passed list of targets.

        'targets' can be a single host/ip, a space-separated list,
        or a comma-separated list
        """

        # comma separated target list
        if "," in targets[0]:
            self.targets = targets[0].split(",")

        # single target or target list
        elif len(targets) == 1:

            # if we have a target file, try to parse it
            if os.path.exists(targets[0]):

                # open the target file and parse the IPs/hosts
                f = open(targets[0])
                lines = f.readlines()
                f.close()

                self.targets = [line.strip() for line in lines if line.strip() != ""]

            # single target
            else:
                self.targets = [targets[0]]
        
        # space separated list
        elif len(targets) > 1:
            self.targets = targets

        # invalid case/sanity check
        else:
            helpers.color(" [!] Invalid targets passed", warning=True)
            targets = None

        # uniqify the hosts we've added to ensure no duplicates
        self.targets = list(set(self.targets))

        # sort the IPs
        helpers.sortIPs(self.targets)


    def resetTargets(self):
        """
        Reset the internal target list.
        """
        self.targets = []


    def listTargets(self):
        """
        Print out the current target or targets set.
        """
        
        print ""
        if not self.targets:
            print helpers.color(" [!] No targets currently set\n", warning=True)

        else:
            print " [*] Current targets:\n"
            for target in self.targets:
                print helpers.color("\t%s" % (target))
            print ""


    def setCreds(self, creds):
        """
        Set the internal credential list.
        """

        # sanity check - skip if the passed list is empty
        if not creds or len(creds) == 0:
            pass
        else:
            # if we have a credential file, parse it and get the results
            if os.path.exists(creds[0]):
                self.creds = self.parseCredfile(creds[0])
            # if we have a cred list passed, split/handle it
            else:
                tempCreds = []
                for cred in creds:
                    # handle individual comma-separated username:pw's
                    if ":" in cred:
                        # split creds by : into username, pw/hash
                        parts = cred.split(":")
                        # append the [username, pw/hash] list to our temporary cred list
                        tempCreds.append( [parts[0], ":".join(parts[1:])] )
                    else:
                        print helpers.color("\n [!] Please enter creds in '(domain/)username:password' or '(domain/)username:LM:NTLM' format\n", warning=True)

                # set the internal cred object to the total of all the parsed credentials
                self.creds = tempCreds 


    def resetCreds(self):
        """
        Reset the internal self.creds list.
        """
        self.creds = []


    def listCreds(self):
        """
        Print out the current credentials set.
        """

        print ""
        if len(self.creds) == 0:
            print helpers.color(" [!] No creds currently set\n", warning=True)

        else:
            print " [*] Current creds:\n"
            for (user, pw) in self.creds:
                # print helpers.color("\t%s" % (cred))
                print helpers.color("\t"+user+" : "+pw)
            print ""

    
    ########################################################################
    #
    # Methods for module interaction.
    #
    ########################################################################

    def setModule(self, moduleName, options=[]):
        """
        Take a module name and jump to that particular module menu.

        options is a list of required_options passed for the module
            of the form [[option, value], [option2, value2], ...]

        if '--run' is passed, the module is executed, skipping
        the interactive menu.
        """

        for (name, module) in self.modules:

            # if we get a module name, jump to that particular menu
            if name == moduleName.lower():

                # if the module has required_options
                if hasattr(module, 'required_options'): 
                    # and setModule() was passed options to set (usually by command line)
                    if len(options) != 0:
                        # try to extract the option/value pairs, and print an error message
                        # if incorrectly formatted
                        for l in options:
                            try:
                                [option,value] = l
                                # if the passed option is a required_option
                                if option.lower() in module.required_options:
                                    # set the value for that option in the module
                                    module.required_options[option.lower()][0] = value
                            except:
                                print helpers.color(" [!] Incorrectly formatted option: '" + l[0]+"'", warning=True)
                                print helpers.color(" [*] Please use OPTION=VALUE format")

                                time.sleep(3)


                # if we have the --run argument, skip the menu
                # and go right to execution and exit after
                if self.args.run:
                    self.runModule(module)
                    sys.exit()

                # otherwise invoke the menu for this module and then return
                #   we should never reach this, but let's sanity check anyway
                else:
                    self.moduleMenu(module)
                    return ""


        # if moduleName isn't found in the loaded modules, print the main menu and an error message
        messages.mainMenu(self.modules, [])
        print helpers.color(" [!] Warning: module '"+moduleName+"' not found!", warning=True)
        print helpers.color(" [!] Pass '-m' to see all available modules.\n", warning=True)


    def moduleCleanup(self, cleanupFile=""):
        """
        Parse a module-procuded .pc cleanup file and run all the appropriate commands.

        If no cleanup file is given, prompt a user for one.
        """

        # sanity check and print an error message if the file doesn't exist
        if not os.path.exists(cleanupFile):
            print helpers.color(" [!] Error: cleanup file "+cleanupFile+" doesn't exist!", warning=True)
        else:

            f = open(cleanupFile)
            lines = f.readlines()
            f.close()
            print ""

            # interate through all of cleanup lines and execute everything as appropriate
            for line in lines:
                try:
                    # the | is our delimiter for the cleaup file
                    parts = [p.strip() for p in line.split("|")]
                    # sleep for X seconds
                    if parts[0].lower() == "sleep":
                        time.sleep(int(parts[1].lower()))
                    if parts[0].lower() == "executecommand" or parts[0].lower() == "command_methods.executecommand":
                        # grab the appropriate arguments and run the specified execute command
                        target, username, password, cmd, triggerMethod = parts[1:]
                        print helpers.color(" [*] Cleaning up " + target)
                        command_methods.executeCommand(target, username, password, cmd, triggerMethod)
                    elif parts[0].lower() == "deletefile" or parts[0].lower() == "smb.deletefile":
                        # grab the appropriate arguments and delete the specified file
                        target, username, password, fileName = parts[1:]
                        print helpers.color(" [*] Removing "+fileName+" from " + target)
                        smb.deleteFile(target, username, password, fileName)
                except Exception as e:
                    print e
                    print helpers.color(" [!] Error: incorrectly formatted cleanup script line: " + line, warning=True)

            print helpers.color("\n [*] Cleanup complete!\n")



    def validateModuleOptions(self, module):
        """
        Ensures that all necessary options for a given module are set appropriately.

        Returns 'True' if everything is good, 'False' otherwise.

        If '--run' is passed, it will sys.exit() on validation errors.
        """

        # if the module has 'self.targets'
        if hasattr(module, "targets"):
            # if there are no targets specified, prompt the user
            if not self.targets or len(self.targets) == 0:
                print helpers.color("\n [!] Error: value for 'targets' is required!", warning=True)
                # if --run is set, exit
                if self.args.run: 
                    print helpers.color(" [!] Please pass '-t target' or '-tL ips.txt'\n", warning=True)
                    sys.exit()
                return False
            # otherwise, set the module's targets to the current target set
            else:
                module.targets = self.targets

        # if the module has 'self.creds'
        if hasattr(module, "creds"):
            # if there are no targets specified, prompt the user
            if not self.creds or len(self.creds) == 0:
                print helpers.color("\n [!] Error: value for 'creds' is required!", warning=True)
                # if --run is set, exit
                if self.args.run: 
                    print helpers.color(" [!] Please pass '-U user -P pw' or '-cF credfile.txt'\n", warning=True)
                    sys.exit()
                return False
            # otherwise, set the module's targets to the current target set
            else:
                module.creds = self.creds

        # if the module has 'required options', parse through everything
        # and ensure all values are filled in
        if hasattr(module, 'required_options'): 

            # iterate through every required option (key, value) pair
            for (key, [value,desc]) in module.required_options.items():

                # special validation case: 'trigger_method' should be wmis or winexe
                if key.lower() == "trigger_method":

                    method = value.lower()
                    # if the method is anything but these three values, prompt
                    if method != "wmis" and method != "winexe" and method != "smbexec":
                        print helpers.color("\n [!] Error: trigger_method must be wmis, winexe, or smbexec!\n", warning=True)
                        # if --run is set, exit
                        if self.args.run: sys.exit()
                        return False
                    # set the module's trigger method to the result
                    else:
                        module.required_options["trigger_method"][0] = method

                # otherwise, just ensure that everything in required_options has a value 
                else:
                    # if the value is empty, print an errror message
                    if value == "":
                        print helpers.color("\n [!] Error: value for '"+key+"' is required!\n", warning=True)
                        # exit if we had --run passed
                        if self.args.run: sys.exit()
                        return False
                    # otherwise assign the non-empty value to the particular option key
                    else:
                        module.required_options[key][0] = value

        # if we get to this point, we assume everything is validated
        return True


    def runModule(self, module):
        """
        Take a particular module, prompt the sure to ensure they
        want to run (skip this if --run is passed) and 
        kick off module execution.

        outputMenu() is then called with the module to display relevant output

        Returns 'True' if run, 'False' otherwise.
        """

        # make sure all options for the module are set before running
        if self.validateModuleOptions(module):

            # confirm running unless we've gotten an argument saying to skip
            choice = "y"
            if not self.args.run:
                choice = raw_input("\n [>] Run [Y]/n? ")

            # if the user choses a default or types [Yy], run everything
            if choice == "" or choice.lower()[0] == "y":

                # nicely print the title and module name
                messages.title()
                sys.stdout.write(" [*] Executing module: " + helpers.color(module.name) + "...")
                sys.stdout.flush()

                # kick off the module's execution
                module.run()

                # display output at the end, as appropriate
                self.outputMenu(module)

            # the module ran
            return True

        # the module didn't run
        else: return False


    ##################################################################
    #
    # Menus
    #
    ##################################################################

    def outputMenu(self, module):
        """
        Takes a module and writes out the appropriate output 
        and informational messages.

        If a module produced output or cleanup, those are written out
        as appropriate.
        """

        # print the main title and module name
        messages.title()
        print " Module: \t" + helpers.color(module.name) + "\n"
        outputFile = ""

        # timestamp we use in pos sible output reporting
        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y.%H%M%S')

        # check if the module has a "self.output" object
        if hasattr(module, 'output'):
            # if the module produced output write it out
            if module.output != "":

                # build our output file path to be PILLAGE_OUTPUT_PATH/modulename/[timestamp].out
                outputPath = settings.PILLAGE_OUTPUT_PATH + module.__module__ + "/"
                outputFile = outputPath + timestamp + ".out"

                # if the output path doesn't exist, create it
                if not os.path.exists(outputPath): os.makedirs(outputPath)
                f = open(outputFile, 'w')
                f.write(module.output)
                f.close()

                # update the activity log with module name + outout
                helpers.updateActivityLog(module.name + "\n" + module.output)

                print helpers.formatLong("Output file:", helpers.color(outputFile), frontTab=False)
                # print " Output file: \t" + helpers.color(outputFile)

                # reset the module 'self.output' in case this module is run again
                module.output = ""

            else:
                print helpers.color(" [!] No output from the module", warning=True)

        # check if the module has a "self.cleanup" object
        if hasattr(module, 'cleanup'):

            # cleanup file structure: command|arg1|arg2|...

            # if the module produced cleanup write it out
            if module.cleanup != "":

                # build our cleanup file path to be PILLAGE_CLEANUP_PATH/modulename/[timestamp].cleanup
                outputPath = settings.PILLAGE_OUTPUT_PATH + module.__module__ + "/"
                cleanupFile = outputPath + timestamp + ".pc"
                
                # if the cleanup path doesn't exist, create it
                if not os.path.exists(outputPath): os.makedirs(outputPath)
                f = open(cleanupFile, 'w')
                f.write(module.cleanup)
                f.close()

                # update the global cleanup log
                helpers.updateCleanupLog(module.cleanup)

                print " Cleanup file: \t" + helpers.color(cleanupFile) + "\n"

                # reset the module 'self.cleanup' in case this module is run again
                module.cleanup = ""

        print "\n [*] Execution completed\n"

        # if --run was passed, cleanup and exit
        if self.args.run:
            self.cleanup()
            sys.exit()
        # if we didn't autorun with --run, prompt for interaction
        else:
            # check if the user wants to display the output file if we got one
            if outputFile != "":
                choice = raw_input(" [>] Display the output file? [y/N] ")
                if choice.lower() == "y":
                    f = open(outputFile)
                    lines = f.readlines()
                    f.close()

                    print helpers.color("\n [*] Output File:\n")

                    for line in lines:
                        print "\t" + line,

                    raw_input("\n [>] press any key to return to the main menu: ")
            else:
                raw_input("\n [>] press any key to return to the main menu: ")


    def credMenu(self):
        """
        Menu to prompt the user for credential options.

        Returns a list of [username, password]
        """

        creds = []
        username, password = None, None

        # set the credential tab-completion to be a file path
        comp = completers.PathCompleter()
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)

        choice = raw_input(" [>] Enter a username or credump file: ")
        print ""

        # if nothing is specified, return without prompting for a user
        if choice == "": return None

        # if the passed string is a file, parse it
        elif os.path.exists(choice):
            creds = self.parseCredfile(choice)

        # if the input is not a file, assume it's a single user
        # and continue prompting for a password
        else:
            username = choice

            choice = raw_input(" [>] Enter a password or LM:NTLM hash: ")
            print ""

            # if nothing is specified, return
            if choice == "": return None

            password = choice

            # append the username/password to out internal cred list
            creds.append( [username, password] )

        return creds


    def targetMenu(self):
        """
        Menu to prompt the user for targets.

        Returns a list of [hosts/ips]

        """

        targets = []

        # set the credential tab-completion to be a file path
        comp = completers.PathCompleter()
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)

        choice = raw_input("\n [>] Enter a target IP or target list: ")
        print ""
        if choice == "": return None

        # if the user input is a target list, try to read it
        if os.path.exists(choice):
            try:
                t = open(choice).readlines()
                # strip out gunk if it's there and just get the hosts/ips
                t = [x.strip() for x in t if x.strip() != ""]
                targets += t
            except:
                print helpers.color(" [!] Error reading target list: " + choice, warning=True)

        # otherwise just append the input host/ip
        else:
            targets.append(choice)

        return targets


    def cleanupMenu(self):
        """
        Menu to prompt the user for a cleanup file.

        Returns a specified cleanup .pc script
        """

        # set the cleanup tab-completion to be a file path
        comp = completers.PathCompleter()
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)

        choice = raw_input("\n [>] Enter a cleanup .pc file: ")
        print ""
        if choice == "": return None
        else: return choice


    def moduleMenu(self, module):
        """
        Main module interaction menu.

        Menu to display a module, its associated information and
        and available options.

        Handles user interaction to set options and run the module.
        """

        # mark this as our currently executing module,
        #   (for purposes of state restore)
        self.currentModule = module

        # initialize the tab-completer for this particular module
        comp = completers.ModuleCompleter(module, self.moduleCommands, self.setOptions, self.dbOptions)
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)

        # print the module name/description/options and available commands
        messages.moduleMenu(module, self.moduleCommands)

        # keep looping the menu until an option is selected that exits this behavior
        while True:

            # prompt the user for a command, redisplaying as long as they press [enter]
            cmd = ""
            while cmd == "": 
                cmd = raw_input(" [>] Please enter a command: ").strip()

            # extract the user-given command and all its options
            parts = cmd.strip().split()


            #
            # The rest of the code below deals with handling the particular entered command
            #

            # reprint the module name/description/options and available commands
            #   show ALL module commands
            if parts[0].lower() == "info" or  parts[0].lower() == "help":
                 messages.moduleMenu(module, self.moduleCommands, showAll=True)

            # return back to the main menu if the user types "back" or "main"
            elif parts[0].lower() == "main" or parts[0].lower() == "back":
                return ""

            # "exit" -> print a message, perform cleanup, hard exit
            elif parts[0].lower() == "exit":
                # perform any cleanup tasks and exit
                print helpers.color("\n [!] Exiting...\n", warning=True)
                self.cleanup()
                sys.exit()

            # 'set' specific module options
            elif parts[0].lower() == "set":

                # we just have 'set'
                if len(parts) == 1:
                    print helpers.color(" [!] ERROR: no value supplied\n", warning=True)

                # we have 'set option', invoke the appropriate menu for targets or creds
                elif len(parts) == 2:
                    
                    option = parts[1].lower()

                    if option.lower() == "targets":
                        self.targets = self.targetMenu()
                    
                    elif option.lower() == "creds":
                        c = self.credMenu()
                        if c:
                            self.creds = c

                # we have 'set option value' manually set the option value
                else:
                    # extract the option and values for the command
                    option = parts[1]
                    values = parts[2:]

                    # 'set targets' -> invoke the setTargets() menu
                    if option.lower() == "targets":
                        self.setTargets(values)

                    # 'set creds' -> invoke the setCreds() menu
                    elif option.lower() == "creds":
                        self.setCreds(values)

                    # validation for 'set trigger_method'
                    elif option.lower() == "trigger_method":
                        # ensure we get a value of 'wmis', 'winexe', or smbexc
                        if values[0].lower() == "wmis" or values[0].lower() == "winexe" or values[0].lower() == "smbexec":
                            module.required_options[option][0] = values[0].lower()
                        else:
                            print helpers.color("\n [!] Error: trigger_method must be wmis, winexe, or smbexec!\n", warning=True)
                    # 'set OPTION VALUE' for required module options
                    else:
                        # case of 'set required_option value'
                        if option.lower() in module.required_options.keys():
                            # set the value section of the module's required_options dictionary
                            module.required_options[option.lower()][0] = " ".join(values)
                        # if an invalid option is specified, print an error message
                        else:
                            print helpers.color(" [!] Invalid option specified", warning=True)

            # handle the "reset" command for 'global' options (targets/creds)
            elif parts[0].lower() == "reset":
                
                # "reset OPTION" passed, clear our that option
                if len(parts) == 2:

                    # extract the command and the option to set
                    c,option = parts

                    # if we get "reset targets", reset the internal target list
                    if option.lower() == "targets":
                        self.resetTargets()
                        print helpers.color("\n [*] Targets reset!\n")

                    # if we get "reset creds", reset the internal cred list
                    elif option.lower() == "creds":
                        self.resetCreds()
                        print helpers.color("\n [*] Credentials reset!\n")

                    # if an invalid option is specified, print an error message
                    else:
                        print helpers.color("\n [!] Error: invalid option\n", warning=True)

            # handle setting global module options
            elif parts[0].lower() == "setg":
                # only "setg" entered, print an error message
                if len(cmd.split()) == 1 or len(cmd.split()) == 2:
                    print helpers.color(" \n [!] Please enter 'setg OPTION VALUE'\n" )                
                else:
                    # set the option globally
                    self.setGlobalOptions([[cmd.split()[1], " ".join(cmd.split()[2:])]])

            # 'list' set targets or creds
            elif parts[0].lower() == "list":

                # "list X" form
                if len(cmd.split()) == 2:
                    
                    opt = cmd.split()[1]

                    # print the current creds for 'list creds'
                    if opt.lower() == "creds":
                        self.listCreds()

                    # print the current creds for 'list targets'
                    elif opt.lower() == "targets":
                        self.listTargets()

                    # if an invalid option is specified, print an error message
                    else:
                        print helpers.color(" [!] Invalid option specified", warning=True)

            # interact with the msf database
            elif parts[0].lower() == "db":

                # if we get just "db" pass to loop the menu again
                if len(cmd.split()) == 1: 
                    pass

                # if we get a "db command"
                if len(cmd.split()) == 2:
                    
                    if cmd.split()[1].lower() == "connect":
                        self.msfdatabase.connect()

                    elif cmd.split()[1].lower() == "list_targets":
                        self.listMSFTargets()

                    elif cmd.split()[1].lower() == "list_creds":
                        self.listMSFCreds()

                    # list the current Cobalt Strike listeners from the MSF database
                    elif cmd.split()[1].lower() == "listeners":
                        self.listCSListeners()

                # if we get "db command option"
                else:
                    # extract the command
                    c = cmd.split()[1].lower()
                    # extract the options
                    opt = " ".join(cmd.split()[2:])

                    # 'db connect DB_STRING'
                    if c == "connect":
                        self.msfdatabase.connect(opt)

                    # 'db add_creds *' handled by addMSFTargets() 
                    elif c == "add_targets":
                        self.addMSFTargets(opt)

                    # 'db add_creds *' handled by addMSFCreds() 
                    elif c == "add_creds":
                        self.addMSFCreds(opt)

                    # add the particular CS listener from the MSF database
                    elif c == "use_listener":
                        self.useCSListener(opt)

            # if the user typed the 'run' command, call runModule(module)
            # to get final confirmation, validate options, and run
            elif parts[0].lower() == "run":

                # laucnh the specific module
                if self.runModule(module):
                    # the module ran
                    return ""
                else: pass

            # if we get an invalid command, print an error message
            else:
                print helpers.color("\n [!] Invalid command\n", warning=True)

        return ""


    def mainMenu(self, showMessage=True):
        """
        Main interactive menu.
        """

        # reset the currently executing module as we're no longer in one
        self.currentModule = None

        # Print the main title, number of modules loaded, and 
        # the available commands for the main menu
        messages.mainMenu(self.modules, self.mainCommands)

        # keep looping the main menu until a module is chosen or the user exits
        while True:

            # set out tab completion with the main menu options on each run
            # as other modules sometimes reset this
            comp = completers.MainMenuCompleter(self.modules, self.mainCommands, self.setOptions, self.dbOptions)
            readline.set_completer_delims(' \t\n;')
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)

            # prompt the user for a command
            cmd = raw_input(' [>] Please enter a command: ').strip()

            # extract the user-given command and all its options
            parts = cmd.strip().split()


            ###############################################################################
            #
            # The rest of the code below deals with handling the particular entered command
            #
            ###############################################################################

            # redisplay the main menu if the user pressed [enter]
            if cmd == "":
                messages.mainMenu(self.modules, self.mainCommands)

            # handle options for the "use" command
            elif parts[0].lower() == "use":

                # if no argument, mimic the "list" command behavior by
                # just displaying all available modules
                if len(cmd.split()) == 1:
                    self.listModules()

                # if we (likely) have a module named passed
                elif len(cmd.split()) == 2:

                    # pull out the module/number to use
                    m = cmd.split()[1]

                    # if we're choosing the module by numbers
                    if m.isdigit() and 0 < int(m) <= len(self.modules):
                        x = 1
                        for (name, module) in self.modules:
                            # if the entered number matches the module #, use that module
                            if int(m) == x:
                                # jump to the particular module menu
                                self.moduleMenu(module)
                                # then reprint the main menu title before looping
                                messages.mainMenu(self.modules, self.mainCommands)
                            x += 1

                    # else choosing the module by name
                    else:
                        for (name, module) in self.modules:
                            # if we find the module specified, kick off the module menu
                            if name == m.lower():
                                # jump to the particular module menu
                                self.moduleMenu(module)
                                # then reprint the main menu title before looping
                                messages.mainMenu(self.modules, self.mainCommands) 

            # handle 'set targets', 'set creds', or global "set option value"
            elif parts[0].lower() == "set":

                # only "set" entered, print an error message
                if len(cmd.split()) == 1:
                    print helpers.color(" \n [!] Please enter 'set targets' or 'set creds'\n" )
                
                # "set target/cred" passed, kick into selection menu for that option
                elif len(cmd.split()) == 2:
                    c,option = cmd.split()

                    # kick into selection menu for targets or creds as appropriate
                    if option.lower() == "targets":
                        t = self.targetMenu()
                        # only set self.targets if the user entered something
                        if t: self.targets = t

                    elif option.lower() == "creds":
                        c = self.credMenu()
                        # only set self.creds if the user entered something
                        if c: self.creds = c

                # 'set target/cred value' passed, set the appropriate value as appropriate
                else:
                    if cmd.split()[1].lower() == "targets":
                        self.setTargets(cmd.split()[2:])

                    elif cmd.split()[1].lower() == "creds":
                        self.setCreds(cmd.split()[2:])

                    # global 'set OPTION VALUE'
                    else:
                        self.setGlobalOptions([[cmd.split()[1], " ".join(cmd.split()[2:])]])

            # handle setting global module options
            elif parts[0].lower() == "setg":
                # only "setg" entered, print an error message
                if len(cmd.split()) == 1 or len(cmd.split()) == 2:
                    print helpers.color(" \n [!] Please enter 'setg OPTION VALUE'\n" )                
                else:
                    # set the option globally
                    self.setGlobalOptions([[cmd.split()[1], " ".join(cmd.split()[2:])]])

            # handle the "reset" command for 'global' options
            elif parts[0].lower() == "reset":
                
                # "reset OPTION" passed - clear out that option
                if len(cmd.split()) == 2:
                    c,option = cmd.split()
                    if option.lower() == "targets":
                        self.resetTargets()
                        print helpers.color("\n [*] Targets reset!\n")
                    elif option.lower() == "creds":
                        self.resetCreds()
                        print helpers.color("\n [*] Credentials reset!\n")
                    else:
                        print helpers.color("\n [!] Error: invalid option\n", warning=True)

            # 'list' modules, current creds, or current targets
            elif parts[0].lower() == "list":

                # if just 'list' list all the currently loaded module
                if len(cmd.split()) == 1:
                    self.listModules()

                # if we have 'list modules/targets/creds'
                elif len(cmd.split()) > 1:
                    
                    opt = cmd.split()[1]

                    if opt.lower() == "modules":
                        self.listModules()

                    elif opt.lower() == "creds":
                        self.listCreds()

                    elif opt.lower() == "targets":
                        self.listTargets()

            # 'db' command -> interact with the msf database
            elif parts[0].lower() == "db":

                if len(cmd.split()) == 1:
                    print helpers.color("\n [!] Please enter a command for 'db'\n", warning=True)

                elif len(cmd.split()) == 2:
                    
                    # connect to the MSf database with the DB string in /etc/veil/settings.py
                    if cmd.split()[1].lower() == "connect":
                        self.msfdatabase.connect()

                    # list the current hosts in the MSF database
                    elif cmd.split()[1].lower() == "list_targets":
                        self.listMSFTargets()

                    # list the current credentials in the MSF database
                    elif cmd.split()[1].lower() == "list_creds":
                        self.listMSFCreds()

                    # list the current Cobalt Strike listeners from the MSF database
                    elif cmd.split()[1].lower() == "listeners":
                        self.listCSListeners()

                elif len(cmd.split()) > 2:

                    c = cmd.split()[1]
                    opt = " ".join(cmd.split()[2:])

                    # connect to the msf database with the passed DB string
                    if c == "connect":
                        self.msfdatabase.connect(opt)

                    # add the particular hosts from the MSF database to our targets
                    elif c == "add_targets":
                        self.addMSFTargets(opt)

                    # add the particular creds from the MSF database to our targets
                    elif c == "add_creds":
                        self.addMSFCreds(opt)

                    # add the particular CS listener from the MSF database
                    elif c == "use_listener":
                        self.useCSListener(opt)


            # if the user types 'exit', perform cleanup functionality and hard exit
            elif parts[0].lower() == "exit":
                print helpers.color("\n [!] Exiting...\n", warning=True)
                self.cleanup()
                sys.exit()

            # clean the output folders
            elif parts[0].lower() == "clean":
                self.cleanOutputFolders()

            # reprint the main help menu
            elif parts[0].lower() == "help":
                messages.mainMenu(self.modules, self.mainCommands) 

            # handle module cleanup scripts
            elif parts[0].lower() == "cleanup":
                # if just "cleanup", prompt the user for a script
                if len(cmd.split()) == 1:

                    choice = raw_input("\n [>] Run the global cleanup file? [y/N] ")

                    if choice.lower() == "y":
                        script = settings.PILLAGE_OUTPUT_PATH + "/cleanup.pc"

                        if script:
                            print "\n [*] Running global cleanup file " + script
                            self.moduleCleanup(script)
                            # remove the global cleanup file after it's run
                            os.system('rm ' + script)
                    else:
                        # otherwise try to prompt for a cleanup script path
                        script = self.cleanupMenu()
                        # if we get a result, pass it to moduleCleanup
                        if script: self.moduleCleanup(script)
                elif len(cmd.split()) == 2:
                    # if we get a script name, pass it straight to the cleanup method
                    self.moduleCleanup(cmd.split()[1])

            # check if we just get a raw number, meaning jump to that numbered module
            elif cmd.isdigit() and 0 < int(cmd) <= len(self.modules):
                x = 1
                for (name, module) in self.modules:
                    # if the entered number matches the module #, use that module
                    if int(cmd) == x:
                        # jump to the particular module menu
                        self.moduleMenu(module)
                        # then reprint the main menu title before looping
                        messages.mainMenu(self.modules, self.mainCommands)
                    x += 1

            # if we get an invalid command, print an error message
            else:
                print helpers.color("\n [!] Invalid command\n", warning=True)

