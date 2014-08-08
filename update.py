#!/usr/bin/python

import platform, os, sys, types, argparse


"""
Setup necessary dependencies.
"""
def setup():
    os.system('clear')
    # Echo Title
    print '========================================================================='
    print ' Veil-Pillage Setup Script | [Updated]: 07.31.2014'
    print '========================================================================='
    print ' [Web]: https://www.veil-framework.com | [Twitter]: @veilframework'
    print '========================================================================='
    print ""

    print " [*] Installing the passing-the-hash toolkit\n"
    # install the passing-the-hash toolkit
    os.system("apt-get install passing-the-hash")

    print " [*] Removing old 'pillage.state' file\n"
    os.system("rm pillage.state")

    try:
        from impacket.dcerpc.v5 import samr, transport, srvs
        if os.path.exists("/usr/local/bin/psexec.py"):
            print " [*] Impacket Already Installed... Skipping."
        else:
            print " [*] Installing impacket...\n"
            # use a revision number we know works :)
            os.system("svn checkout http://impacket.googlecode.com/svn/trunk/@1252 /tmp/impacket/")
            os.system("cd /tmp/impacket/ && python setup.py install")

    except:
        print " [*] Installing impacket...\n"
        # use a revision number we know works :)
        os.system("svn checkout http://impacket.googlecode.com/svn/trunk/@1252 /tmp/impacket/")
        os.system("cd /tmp/impacket/ && python setup.py install")


"""
Parse the metaspoit properties.ini file and return the
msf databasename, username, and password.
"""
def parseMSFConfig(configFile=None):

    if not configFile:
        configFile = "/opt/metasploit/properties.ini"

    try:

        f = open(configFile)
        config = f.readlines()
        f.close()

        databasename, username, password, dbPort = None, None, None, None

        for line in config:
            if "rapid7_database_name" in line:
                databasename = line.split("=")[1].strip()
            if "rapid7_database_user" in line:
                username = line.split("=")[1].strip()
            if "rapid7_database_password" in line:
                password = line.split("=")[1].strip()
            if "postgres_port" in line:
                dbPort = line.split("=")[1].strip()

        # user:pass@host:port/db
        return "%s:%s@127.0.0.1:%s/%s" %(username, password, dbPort, databasename)

    except:
        print " [!] Error parsing file: " + str(configFile)
        return ""


"""

Take an options dictionary and update /etc/veil/settings.py

"""
def generateConfig(options):
    
    config = """#!/usr/bin/python

##################################################################################################
#
# Veil-Framework configuration file                                               
#
# Run update.py to automatically set all these options to their defaults.
#
##################################################################################################



#################################################
#
# General system options
#
#################################################

"""
    print "\n Veil-Framework configuration:"

    config += '# OS to use (Kali/Backtrack/Debian/Windows)\n'
    config += 'OPERATING_SYSTEM="' + options['OPERATING_SYSTEM'] + '"\n\n'
    print "\n [*] OPERATING_SYSTEM = " + options['OPERATING_SYSTEM']

    config += '# Terminal clearing method to use\n'
    config += 'TERMINAL_CLEAR="' + options['TERMINAL_CLEAR'] + '"\n\n'
    print " [*] TERMINAL_CLEAR = " + options['TERMINAL_CLEAR']

    config += '# Path to temporary directory\n'
    config += 'TEMP_DIR="' + options["TEMP_DIR"] + '"\n\n'
    print " [*] TEMP_DIR = " + options["TEMP_DIR"]

    config += '# Default options to pass to msfvenom for shellcode creation\n'
    config += 'MSFVENOM_OPTIONS="' + options['MSFVENOM_OPTIONS'] + '"\n\n'
    print " [*] MSFVENOM_OPTIONS = " + options['MSFVENOM_OPTIONS']
    
    config += '# The path to the metasploit framework, for example: /usr/share/metasploit-framework/\n'
    config += 'METASPLOIT_PATH="' + options['METASPLOIT_PATH'] + '"\n\n'
    print " [*] METASPLOIT_PATH = " + options['METASPLOIT_PATH']

    config += '# The path to pyinstaller, for example: /usr/share/pyinstaller/\n'
    config += 'PYINSTALLER_PATH="' + options['PYINSTALLER_PATH'] + '"\n\n'
    print " [*] PYINSTALLER_PATH = " + options['PYINSTALLER_PATH'] + "\n"


    config += """
#################################################
#
# Veil-Evasion specific options
#
#################################################

"""
    config += '# Veil-Evasion install path\n'
    config += 'VEIL_EVASION_PATH="' + options['VEIL_EVASION_PATH'] + '"\n\n'
    print " [*] VEIL_EVASION_PATH = " + options['VEIL_EVASION_PATH']
    
    source_path = os.path.expanduser(options["PAYLOAD_SOURCE_PATH"])
    config += '# Path to output the source of payloads\n'
    config += 'PAYLOAD_SOURCE_PATH="' + source_path + '"\n\n'
    print " [*] PAYLOAD_SOURCE_PATH = " + source_path

    # create the output source path if it doesn't exist
    if not os.path.exists(source_path): 
        os.makedirs(source_path)
        print " [*] Path '" + source_path + "' Created"
    
    compiled_path = os.path.expanduser(options["PAYLOAD_COMPILED_PATH"])
    config += '# Path to output compiled payloads\n'
    config += 'PAYLOAD_COMPILED_PATH="' + compiled_path +'"\n\n'
    print " [*] PAYLOAD_COMPILED_PATH = " + compiled_path

    # create the output compiled path if it doesn't exist
    if not os.path.exists( compiled_path ): 
        os.makedirs( compiled_path )
        print " [*] Path '" + compiled_path + "' Created"

    handler_path = os.path.expanduser(options["HANDLER_PATH"])
    # create the output compiled path if it doesn't exist
    if not os.path.exists( handler_path ): 
        os.makedirs( handler_path )
        print " [*] Path '" + handler_path + "' Created"

    config += '# Whether to generate a msf handler script and where to place it\n'
    config += 'GENERATE_HANDLER_SCRIPT="' + options['GENERATE_HANDLER_SCRIPT'] + '"\n'
    print " [*] GENERATE_HANDLER_SCRIPT = " + options['GENERATE_HANDLER_SCRIPT']
    config += 'HANDLER_PATH="' + handler_path + '"\n\n'
    print " [*] HANDLER_PATH = " + handler_path

    hash_path = os.path.expanduser(options["HASH_LIST"])
    config += '# Running hash list of all payloads generated\n'
    config += 'HASH_LIST="' + hash_path + '"\n\n'
    print " [*] HASH_LIST = " + hash_path + "\n"


    config += """
#################################################
#
# Veil-Catapult specific options
#
#################################################

"""
    config += '# Veil-Catapult install path\n'
    config += 'VEIL_CATAPULT_PATH="' + options['VEIL_CATAPULT_PATH'] + '"\n\n'
    print " [*] VEIL_CATAPULT_PATH = " + options['VEIL_CATAPULT_PATH']

    catapult_resource_path = os.path.expanduser(options["CATAPULT_RESOURCE_PATH"])
    # create the catapult resource path if it doesn't exist
    if not os.path.exists( catapult_resource_path ): 
        os.makedirs( catapult_resource_path )
        print " [*] Path '" + catapult_resource_path + "' Created"
    config += '# Path to output Veil-Catapult resource/cleanup files\n'
    config += 'CATAPULT_RESOURCE_PATH="' + catapult_resource_path + '"\n\n'
    print " [*] CATAPULT_RESOURCE_PATH = " + catapult_resource_path


    config += '# Whether to automatically spawn a handler for a Veil-Evasion produced payloads\n'
    config += 'SPAWN_CATAPULT_HANDLER="' + options['SPAWN_CATAPULT_HANDLER'] + '"\n\n'
    print " [*] SPAWN_CATAPULT_HANDLER = " + options['SPAWN_CATAPULT_HANDLER'] + "\n"



    config += """
#################################################
#
# Veil-Pillage specific options
#
#################################################

"""
    config += '# Veil-Pillage install path\n'
    config += 'VEIL_PILLAGE_PATH="' + options['VEIL_PILLAGE_PATH'] + '"\n\n'
    print " [*] VEIL_PILLAGE_PATH = " + options['VEIL_PILLAGE_PATH']

    pillage_output_path = os.path.expanduser(options["PILLAGE_OUTPUT_PATH"])
    # create the catapult resource path if it doesn't exist
    if not os.path.exists( pillage_output_path ): 
        os.makedirs( pillage_output_path )
        print " [*] Path '" + pillage_output_path + "' Created"
    config += '# Path to output Veil-Pillage output files\n'
    config += 'PILLAGE_OUTPUT_PATH="' + pillage_output_path + '"\n\n'
    print " [*] PILLAGE_OUTPUT_PATH = " + pillage_output_path

    # try to parse the local properties.ini for metasploit
    configString = parseMSFConfig()
    config += '# MSF database connction string of the form user:pass@host:port/db\n'
    config += 'MSF_DATABASE="' + configString + '"\n\n'
    print " [*] MSF_DATABASE = " + configString
    
    config += '# Automatically connect to the MSF database\n'
    config += 'MSF_AUTOCONNECT="' + options["MSF_AUTOCONNECT"] + '"\n\n'
    print " [*] MSF_AUTOCONNECT = " + options["MSF_AUTOCONNECT"]

    # whether to prompt the user to restore any save state file
    config += '# Whether to prompt the user to restore any state file\n'
    config += 'PILLAGE_STATE_RESTORE="' + options["PILLAGE_STATE_RESTORE"] + '"\n\n'
    print " [*] PILLAGE_STATE_RESTORE = " + options["PILLAGE_STATE_RESTORE"]

    if platform.system() == "Linux":
        # create the output compiled path if it doesn't exist
        if not os.path.exists("/etc/veil/"): 
            os.makedirs("/etc/veil/")
            print " [*] Path '/etc/veil/' Created"
        f = open("/etc/veil/settings.py", 'w')
        f.write(config)
        f.close()
        print "\n Configuration File Written To '/etc/veil/settings.py'\n"
    else:
        print " [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED"
        sys.exit()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--defaults', action='store_true', help='Use default values for the config and don\'t read existing information.')
    args = parser.parse_args()

    options = {}
    # set so veil-evasion and veil-catapult options are not affected? how to handle this....
    if platform.system() == "Linux":
        
        # check /etc/issue for the exact linux distro
        issue = open("/etc/issue").read()
        
        if issue.startswith("Kali"):
            options["OPERATING_SYSTEM"] = "Kali"
            options["TERMINAL_CLEAR"] = "clear"
            options["METASPLOIT_PATH"] = "/usr/share/metasploit-framework/"
            if os.path.isdir('/usr/share/pyinstaller'):
                options["PYINSTALLER_PATH"] = "/usr/share/pyinstaller/"
            else:
                options["PYINSTALLER_PATH"] = "/opt/pyinstaller-2.0/"
        elif issue.startswith("BackTrack"):
            options["OPERATING_SYSTEM"] = "BackTrack"
            options["TERMINAL_CLEAR"] = "clear"
            options["METASPLOIT_PATH"] = "/opt/metasploit/msf3/"
            options["PYINSTALLER_PATH"] = "/opt/pyinstaller-2.0/"
        else:
            options["OPERATING_SYSTEM"] = "Linux"
            options["TERMINAL_CLEAR"] = "clear"
            msfpath = raw_input(" [>] Please enter the path of your metasploit installation: ")
            options["METASPLOIT_PATH"] = msfpath
            options["PYINSTALLER_PATH"] = "/opt/pyinstaller-2.0/"
        
        # last of the general options
        options["TEMP_DIR"]="/tmp/"
        options["MSFVENOM_OPTIONS"]=""

        # Veil-Evasion specific options
        # default to assuming Veil-Evasion is at the same level as Veil-Pillage
        veil_evasion_path = "/".join(os.getcwd().split("/")[:-1]) + "/Veil-Evasion/"
        options["VEIL_EVASION_PATH"] = veil_evasion_path
        options["PAYLOAD_SOURCE_PATH"] = "~/veil-output/source/"
        options["PAYLOAD_COMPILED_PATH"] = "~/veil-output/compiled/"
        options["GENERATE_HANDLER_SCRIPT"] = "True"
        options["HANDLER_PATH"] = "~/veil-output/handlers/"
        options["HASH_LIST"] = "~/veil-output/hashes.txt"

        # Veil-Catapult specific options
        # default to assuming Veil-Catapult is at the same level as Veil-Pillage
        veil_catapult_path = "/".join(os.getcwd().split("/")[:-1]) + "/Veil-Catapult"
        options["VEIL_CATAPULT_PATH"] = veil_catapult_path
        options["CATAPULT_RESOURCE_PATH"] = "~/veil-output/catapult/"
        options["SPAWN_CATAPULT_HANDLER"] = "false"

        # Veil-Pillage specific options
        veil_pillage_path = os.getcwd()
        options["VEIL_PILLAGE_PATH"] = veil_pillage_path
        options["PILLAGE_OUTPUT_PATH"] = "~/veil-output/pillage/"
        options["MSF_AUTOCONNECT"] = "True"
        options["PILLAGE_STATE_RESTORE"] = "True"
    
    # unsupported platform... 
    else:
        print " [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED"
        sys.exit()


    # install any needed depencies
    setup()

    # if --default is not passed, try to read in the existing config and parse its values
    if not args.defaults:
        # see if a config currently exists, and if it does
        # parse it and return the existing values
        if os.path.exists("/etc/veil/settings.py"):
            try:
                sys.path.append("/etc/veil/")
                import settings
                # print dir(types)
                # print type(settings.MSF_DATABASE)
                existingOptions = [(str(a),(settings.__dict__.get(a))) for a in dir(settings) if isinstance(settings.__dict__.get(a), types.StringType) and not a.startswith("__")]
                
                # go through all the existing options and set the current
                # option values for what's found so existing option configs
                # are preserved
                for (option, value) in existingOptions:
                    if option in options:
                        options[option] = value

            except ImportError:
                # if the /etc/veil/settings.py file doesn't exist, just skip
                pass

    # take all the configuration options and create the config
    generateConfig(options)
