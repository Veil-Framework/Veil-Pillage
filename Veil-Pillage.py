#!/usr/bin/python

"""
Veil-Pillage: post-explotation framework
    https://www.veil-framework.com/

This is the launcher for the Veil-Pillage post-explotation framework.
It mostly just handles the command line options - the main logic 
is contained in ./lib/pillage.py


By: @harmj0y

"""

import sys, argparse

# import the necessary pillage libraries from ./lib/
from lib import pillage
from lib import helpers

if __name__ == '__main__':

    try:

        parser = argparse.ArgumentParser()

        # create our arugment parse groups and add whatever we need
        group = parser.add_argument_group('General options')
        group.add_argument('-m', metavar="module [OPTION=VALUE]", nargs='*', help='Module to use, followed by module options. Lists modules available if none specified')
        group.add_argument('-o', metavar="OPTION=value", nargs='*', help='Global options')
        group.add_argument('-s', metavar="restore.state", nargs='?', help='Use specific restore file')
        group.add_argument('--norestore', action='store_true', help='Don\'t do any state restore')
        group.add_argument('--run', action='store_true', help='Run the specified module without confirmation')
        group.add_argument('--clean', action='store_true', help='Clean out all module result directories')
        group.add_argument('--cleanup', metavar="cleanup.pc", nargs='?', help='Run a module cleanup file')

        group = parser.add_argument_group('Target options')
        group.add_argument('-t', metavar="TARGET", help='Specific IP to target')
        group.add_argument('-tL', metavar="targetlist.txt", help='IP target list')

        group = parser.add_argument_group('Authentication options')
        group.add_argument('-U', metavar="(DOMAIN/)USERNAME", help='username to use, domain is optional')
        group.add_argument('-P', metavar="PASSWORD", help='Password/lm:ntlm hash to use')
        group.add_argument('-cF', metavar="CREDFILE", help='Hashdump or [user pw] credential file to use')

        # Veil-Evasion/payload options
        group = parser.add_argument_group('Veil-Evasion payload options')
        group.add_argument('-p', metavar="PAYLOAD", nargs='?', const="list", help='Veil-Evasion payload module to use for a module if applicable')
        group.add_argument('-c', metavar='OPTION=value', nargs='*', help='Custom Veil-Evasion payload module options')
        group.add_argument('--msfpayload', metavar="windows/meterpreter/reverse_tcp", nargs='?', help='Metasploit payload to generate for shellcode payloads')
        group.add_argument('--msfoptions', metavar="OPTION=value", nargs='*', help='Options for the specified metasploit payload')
        group.add_argument('--custshell', metavar="\\x00...", help='Custom shellcode string to use')

        # parse our arguments
        args = parser.parse_args()

        # instantiate the main pillage controller object with the argument object
        pillage = pillage.Pillage(args)

        # check if we're passed a flag to clean the output folders
        if args.clean:
            pillage.cleanOutputFolders()

        # if we're passed a cleanup file run it with moduleCleanup(file)
        if args.cleanup:
            pillage.moduleCleanup(args.cleanup)
            sys.exit()

        # if we -o options passed, set them globally
        if args.o:
            options = [ a.split("=") for a in args.o]
            pillage.setGlobalOptions(options)

        # if just -m is passed, list all the modules
        if args.m == []:
            pillage.listModules()
            sys.exit()
        # use interactive menu if -m isn't passed
        if not args.m:
            pillage.mainMenu()
        # otherwise, if a module is passed
        else:
            # try to get the module name and any options
            if len(args.m) == 1:
                # if we just have a module name, jump to that module menu
                pillage.setModule(args.m[0])
                # then back to the main menu if we get an exit
                pillage.mainMenu()
            else:
                # otherwise, set the particular options and then jump to the menu
                module = args.m[0]
                options = [ a.split("=") for a in args.m[1:]]
                pillage.setModule(module, options)
                # then back to the main menu if we get an exit
                pillage.mainMenu()

        # NOTE- if you want to run a particular module, do:
        # pillage.runModule('module/blah') to autorun without user interaction
        # AFTER you've set the appropriate options :)

        # perform any cleanup tasks and exit
        pillage.cleanup()
        sys.exit()

    # catch keyboard interrupts/rage-quits (ctrl+c)
    except KeyboardInterrupt:
        print helpers.color("\n\n [!] Rage-quit, exiting...\n", warning=True)
        # perform any cleanup tasks and exit
        try: pillage.cleanup()
        except: pass
        sys.exit()

    # catch all other exceptions and try to clean up gracefully
    except Exception as e:
        print helpers.color("\n\n [!] Error: "+str(e), warning=True)
        print helpers.color("\n [!] Saving state and exiting...\n", warning=True)
        try: pillage.cleanup()
        except: pass
        sys.exit()