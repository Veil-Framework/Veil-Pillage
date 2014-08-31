"""
Common terminal messages used across Veil-Pillage.
"""

from lib import helpers

import os, sys


version = "1.0.1"

###############################################################
#
# Messages
#
###############################################################

def title():
    """
    Print the tool title, with version.
    """
    os.system('clear')
    print "========================================================================="
    print " Veil-Pillage: post-explotation framework | [Version]: " + version
    print '========================================================================='
    print ' [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework'
    print '========================================================================='
    print ""


def commands(commands):
    """
    Print a formatted output of the passed commands list
        commands if of the format [(cmd, desc),...]
    """
    
    if len(commands) != 0:
        print "\n Available commands:\n"
        
        # list commands in sorted order
        #for cmd in sorted(commands.iterkeys(), reverse=True):
        for (cmd, desc) in commands:
            
            print "\t%s\t%s" % ('{0: <12}'.format(cmd), desc)

    print ""


def moduleMenu(module, moduleCommands, showAll=False):
    """
    Print the main title, the name and description of the passed
    module, and the module's required options and values.

    module - the module to display information options
    moduleCommands - the available module commands to display
    """

    title()

    # nicely print the module name and description
    print " Module: \t" + helpers.color(module.name)
    print helpers.formatLong("Description:", module.description, frontTab=False)

    # nicely print out the module's required options and values
    if hasattr(module, 'required_options'):
        print "\n Required Options:\n"

        print " Name\t\t\tCurrent Value\tDescription"
        print " ----\t\t\t-------------\t-----------"

        # sort the dictionary by key before we output, so it looks nice
        for key in sorted(module.required_options.iterkeys()):
            desc = helpers.formatDesc(module.required_options[key][1])
            print " %s\t%s\t%s" % ('{0: <16}'.format(key), '{0: <8}'.format(module.required_options[key][0]), desc)


    # print out all the available commands for this module
    if showAll:
        moduleCommandsShow = moduleCommands
    # by default skip "list", "set", "reset", and "db" as these are also on the main menu
    else:
        moduleCommandsShow = [(cmd,desc) for (cmd,desc) in moduleCommands if cmd not in ["list", "set", "setg", "reset", "db"]]
    
    # display the stripped command list
    commands(moduleCommandsShow)


def mainMenu(modules, mainCommands):
    """
    Print the main title, number of modules loaded, and 
    the available commands for the main menu
    """

    title()
    print " Main Menu\n"
    print "\t" + helpers.color(str(len(modules))) + " modules loaded\n"
    commands(mainCommands)
