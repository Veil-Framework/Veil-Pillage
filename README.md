#Veil-Pillage

Veil-Pillage is a post-exploitation framework and a part of the [Veil framework](https://www.veil-framework.com/).

Veil-Pillage was built by [@harmj0y](https://twitter.com/harmj0y) is currently under active support by @harmj0y with help from the [@VeilFramework](https://twitter.com/VeilFramework) team.

## Usage:

Start everything up with ./Veil-Pillage.py. All the modules in ./modules/* will automatically be loaded up with their path reflected in the menu (i.e. enumeration/host/credential_validation).

First, you need to specify a target or target(s), and a set of credentials:
    
    Targets can be set with "set targets 192.168.1.1 192.168.1.2" 
                        or  "set targets 192.168.1.1,192.168.1.2"
                        or  "set targets hostlist.txt"
                        or  "set targets"
                        or  cli with "-t target"
                        or  cli with "-tL target_list.txt"

    Credentials can be set with "set creds (domain/)username:password"
                            or  "set creds (domain/)username:LM:NTLM"
                            or  "set creds"
                            or  cli with "-U user -P password"
                            or  clie with "-cF credential_file" (hashdump or tab-separated)

Then you can launch a given module with "use path/name" or "use [module #]". 
All modules can be listed with "list modules", and the paths for 'use' are tab-completable.

Once in a module menu, you can modify given paramters for the module with 'set X'. 
After everything is set, type run, Y to confirm, and the module will execute.

Status updates will display during execution, and any output will be stored in an output file that is named on the completion screen. Output is stored in the veil-output folder/pillage/modulename/timestamp.out. If there is a cleanup file, it will be stored in the same location with a *.pc extension.

To cleanup, type "cleanup /path to *.pc file" and Veil-Pillage will try to restore all targets to their original state.


### Random Features:

* the current program state, including set credentials, targets, and all module options,
is saved off to a state file on exit or rage-quit
    user is prompted for restore on user start - can turn this off with arguments or settings.py value
    -manual restore file name can be specified with "-s pillage.state"
    "--norestore" skips the state restore prompt

* should parse connection information for the MSF database automatically, and auto-connect to the database

* can list hosts or creds from the MSF database with "db list_targets/list_creds"

* can add hosts/creds from the MSF database with "db add_targets/add_creds 1,2,3"
    where 1,2,3 is the selection displayed from list_targets/list_creds

* Module options like 'lhost' can be set globally from the main menu, i.e. "set lhost 192.168.1.100"

* Complete command line options are availabe, run ./Veil-Pillage.py for a list.

* Almost everything that can be tab-completable has been bilt to be. Commands, options, files paths, etc.

* Variables can be reset with "reset varname"

* can set options globally for every module with "set lhost 192.168.1.100" on the main menu,
or cli with "-o lhost=192.168.1.100"

* 'clean' or "--clean" cleans out the output folders

* the module to jump to can be set cli with "-m module/name OPTION=value..."

* ties into Veil-Evasion for most payload_delivery/* modules


##Software Requirements:

###Kali

Currently, only Kali linux x86 is officially supported. 

We recommend that users install this tool as a part of the [Veil superproject](https://github.com/Veil-Framework/Veil) to take advantage of the full functionality of the [Veil-Framework](https://www.veil-framework.com).

[Veil-Evasion](https://github.com/Veil-Framework/Veil-Evasion/) is required for payload generation.

[Impacket](https://code.google.com/p/impacket/) and the [passing-the-hash toolkit](http://passing-the-hash.blogspot.com/) are required for payload delivery and triggering.

##Setup (tldr;)

Install the [Veil superproject](https://github.com/Veil-Framework/Veil) and run the top level Veil/update.sh script to install all necessary dependencies and build a common configuration file at /etc/veil/settings.py

If you install this separately, run the ./update.py script on each major pull update to ensure all dependencies and configurations are correct.

Please just install the Veil superproject. All the pieces of the Veil-Framework were built to work together. Installing them separately is a recipe for grief and support requests.

## Structure

A quick overview of the structure of everything:

* ./Veil-Pillage.py           -   the main launcher for the tool, parses arguments and calls ./lib/pillage.py
* ./update.py                 -   the setup and update logic for the framework

* ./modules/*                 -   usable modules organized roughly by function
* ./modules/template.py       -   example module template

* ./lib/*                     -   reusable library methods
* ./lib/pillage.py            -   the main control logic for the framework, including menu interfaces
* ./lib/helpers.py            -   various misc helper methods
* ./lib/command_methods.py    -   methods to execute specific commands on hosts, use executeResult() and executeCommand()
* ./lib/delivery_methods.py   -   methods to delivery payloads to hosts (upload, host, powershell, etc.)
* ./lib/impacket_*            -   impacket libraries adapted for our use
* ./lib/http.py               -   http related methods (i.e. temp http server)
* ./lib/msfdatabase.py        -   abtracts out interaction for the local msfdatabase
* ./lib/smb.py                -   smb related methods, including upload/delete/tempserver/etc.

* ./data/*                    -   various data elements needed by modules (i.e. PowerSploit scripts)

* ./tools/*                   -   misc tools for use with the framework

