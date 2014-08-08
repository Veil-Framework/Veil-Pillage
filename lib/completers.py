"""

Contains any classes used for tab completion.

Reference - http://stackoverflow.com/questions/5637124/tab-completion-in-pythons-raw-input

"""

import readline, commands, re, os


class MainMenuCompleter(object):
    """
    Class used for tab completion of the main Controller menu
    
    Takes a list of available commands, loaded modules,
    options for "set" and "db" commands.
    
    """

    def __init__(self, modules, commands, setOptions, dbOptions):
        
        # extract the commands from the (command, description) tuples
        self.commands = [cmd for (cmd,desc) in commands]
        self.modules = modules

        # "set" and "db" are global commands with specific options
        self.setOptions = setOptions
        self.dbOptions = dbOptions


    # the following three methods are used for path completion
    def _listdir(self, root):
        """
        Complete a directory path.
        """
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        """
        Complete a file path.
        """
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
                for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_path(self, args):
        """
        Entry point for path completion.

        Invoke anywhere with "complete_path(args)"
        """
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])


    def complete_cleanup(self, args):
        """
        Tab complete the "cleanup" command by appending the
        current path completer.
        """
        return self.complete_path(args)


    def complete_use(self, args):
        """
        Complete the "use" command, returning the appropriate module tree.
            i.e. "enumeration/blah/blah2"
        """

        res = []
        modules = []

        for (name, payload) in self.modules:
            modules.append(name)

        # return all modules if we just have "use"
        if len(args[0].split("/")) == 1:
            res = [ m for m in modules if m.startswith(args[0])] + [None]

        else:
            # get the language
            lang = args[0].split("/")[0]
            # get the rest of the paths
            rest = "/".join(args[0].split("/")[1:])

            modules = []
            for (name, payload) in self.modules:

                parts = name.split("/")

                # iterate down the split parts so we can handle the nested payload structure
                for x in xrange(len(parts)):

                    # if the first part of the iterated payload matches the language, append it
                    if parts[x] == lang:
                        modules.append("/".join(parts[x+1:]))

                # ...this is all black magic I tell you!
                res = [ lang + '/' + m + ' ' for m in modules if m.startswith(rest)] + [None]
                
        return res

    
    def complete_set(self, args):
        """
        Complete the "set" command for whatever options available.
        """

        options = [option for (option,desc) in self.setOptions]

        # show all the available options to set
        if len(args) == 0:
            return [o for o in options] + [None]

        # complete part of an existing option
        elif len(args) == 1:
            return [o + ' ' for o in options if o.startswith(args[0])] + [None]

        elif args[0] != "":
            # path complete for 'set targets' or 'set creds'
            if args[0].strip().lower() == "targets" or args[0].strip().lower() == "creds":
                return self.complete_path(args)
            else:
                return [None]

        # if we've exhausted our options, return nothing
        else:
            return [None]
        
        return res


    def complete_setg(self, args):
        """
        Complete the "setg" command for global options
        """

        options = [option for (option,desc) in self.setOptions]

        # show all the available options to set
        if len(args) == 0:
            return [o for o in options] + [None]

        # complete part of an existing option
        elif len(args) == 1:
            return [o + ' ' for o in options if o.startswith(args[0])] + [None]

        elif args[0] != "":
            # path complete for 'set targets' or 'set creds'
            if args[0].strip().lower() == "targets" or args[0].strip().lower() == "creds":
                return self.complete_path(args)
            else:
                return [None]

        # if we've exhausted our options, return nothing
        else:
            return [None]
        
        return res


    def complete_reset(self, args):
        """
        Complete the "reset" command for whatever options available.

        Uses the same passed option list as "set".
        """

        options = [option for (option,desc) in self.setOptions]

        # show all the available options to set
        if len(args) == 0:
            return [o for o in options] + [None]

        # complete part of an existing option
        elif len(args) == 1:
            return [o + ' ' for o in options if o.startswith(args[0])] + [None]

        # if we've exhausted our options, return nothing
        else:
            return [None]
        
        return res


    def complete_db(self, args):
        """
        Complete the "db" command for whatever options available.
        """

        options = [option for (option,desc) in self.dbOptions]

        # show all the available options to set
        if len(args) == 0:
            return [o for o in options] + [None]

        # complete part of an existing option
        elif len(args) == 1:
            return [o + ' ' for o in options if o.startswith(args[0])] + [None]

        # if we've exhausted our options, return nothing
        else:
            return [None]
        
        return res


    def complete_list(self, args):
        """
        Complete the "list" command for whatever options available.
        """

        options = ["modules", "targets", "creds"]

        # show all the available options to set
        if len(args) == 0:
            return [o for o in options] + [None]

        # complete part of an existing option
        elif len(args) == 1:
            return [o + ' ' for o in options if o.startswith(args[0])] + [None]

        # if we've exhausted our options, return nothing
        else:
            return [None]
        
        return res
        

    def complete(self, text, state):
        """
        Generic readline completion entry point.
        """

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()
        
        # show all commands
        if not line:
            return [c + ' ' for c in self.commands][state]
            
        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')
            
        # resolve command to the implementation functions (above)
        cmd = line[0].strip()
        if cmd in self.commands:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]
            
        results = [ c + ' ' for c in self.commands if c.startswith(cmd)] + [None]
        
        return results[state]


class ModuleCompleter(object):
    """
    Class used for tab completion of the module tree (blah/module).
    """

    def __init__(self, module, commands, setOptions, dbOptions):

        self.commands = [cmd for (cmd,desc) in commands]
        self.module = module
        self.setOptions = setOptions
        self.dbOptions = dbOptions

    # the following three methods are used for path completion
    def _listdir(self, root):
        """
        Complete a directory path.
        """
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        """
        Complete a file path.
        """
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
                for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_path(self, args):
        """
        Entry point for path completion.

        Invoke anywhere with "complete_path(args)"
        """
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])
        

    def complete_set(self, args):
        """
        Complete the "set" command for whatever options available.
        """

        # existing "set" options declared in ./lib/pillage.py
        options = [option for (option,desc) in self.setOptions]

        # if there are 'required_options' for this module, add
        # them to the autocomplete set
        if hasattr(self.module, 'required_options'):
        
            # add the 'required_options' to the existing set options
            options = options + [k for k in sorted(self.module.required_options.iterkeys())]

            # if we have a resolved result            
            if args[0] != "":

                # make "targets" and "creds" path-completed
                if args[0].strip().lower() == "targets" or args[0].strip().lower() == "creds":
                    return self.complete_path(args)

                # make "exe_path", "file_path", and "handler_script" path-complete
                elif args[0].strip().lower() == "exe_path" or args[0].strip().lower() == "handler_script" or args[0].strip().lower() == "file_path":
                    return self.complete_path(args)

                # if we have "set trigger_method " auto tab-complete the default, wmis
                elif args[0].strip().lower() == "trigger_method":
                    return ["wmis"] + [None]

                # auto-complete the local ip for lhost
                elif args[0].strip().lower() == "lhost":
                    res = [commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]] + [None]

                # tab \\LHOST\ for a unc_path
                elif args[0].strip().lower() == "unc_path":
                    res = ["\\\\" + commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]+"\\"] + [None]
                    return self.complete_path(args)

                else:
                    # complete the command in the list ONLY if it's partially completed
                    res = [ o + ' ' for o in options if (o.startswith(args[0]) and o != args[0] )] + [None]

            else:
                # return all required_options available to 'set'
                res = [ o + ' ' for o in options] + [None]

        return res


    def complete_setg(self, args):
        """
        Complete the "set" command for whatever options available.
        """

        # existing "set" options declared in ./lib/pillage.py
        options = [option for (option,desc) in self.setOptions]

        # if there are 'required_options' for this module, add
        # them to the autocomplete set
        if hasattr(self.module, 'required_options'):
        
            # add the 'required_options' to the existing set options
            options = options + [k for k in sorted(self.module.required_options.iterkeys())]

            # if we have a resolved result            
            if args[0] != "":

                # make "targets" and "creds" path-completed
                if args[0].strip().lower() == "targets" or args[0].strip().lower() == "creds":
                    return self.complete_path(args)

                # make "exe_path", "file_path", and "handler_script" path-complete
                elif args[0].strip().lower() == "exe_path" or args[0].strip().lower() == "handler_script" or args[0].strip().lower() == "file_path":
                    return self.complete_path(args)

                # if we have "set trigger_method " auto tab-complete the default, wmis
                elif args[0].strip().lower() == "trigger_method":
                    return ["wmis"] + [None]

                # auto-complete the local ip for lhost
                elif args[0].strip().lower() == "lhost":
                    res = [commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]] + [None]

                # tab \\LHOST\ for a unc_path
                elif args[0].strip().lower() == "unc_path":
                    res = ["\\\\" + commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]+"\\"] + [None]
                    return self.complete_path(args)

                else:
                    # complete the command in the list ONLY if it's partially completed
                    res = [ o + ' ' for o in options if (o.startswith(args[0]) and o != args[0] )] + [None]

            else:
                # return all required_options available to 'set'
                res = [ o + ' ' for o in options] + [None]

        return res


    def complete_list(self, args):
        """
        Complete the "list" command for whatever options available.
        """

        options = ["targets", "creds"]

        # show all the available options to set
        if len(args) == 0:
            return [o for o in options] + [None]

        # complete part of an existing option
        elif len(args) == 1:
            return [o + ' ' for o in options if o.startswith(args[0])] + [None]

        # if we've exhausted our options, return nothing
        else:
            return [None]
        
        return res


    def complete_reset(self, args):
        """
        Complete the "reset" command for whatever options available.

        Uses the same passed option list as "set".
        """

        options = [option for (option,desc) in self.setOptions]

        # show all the available options to set
        if len(args) == 0:
            return [o for o in options] + [None]

        # complete part of an existing option
        elif len(args) == 1:
            return [o + ' ' for o in options if o.startswith(args[0])] + [None]

        # if we've exhausted our options, return nothing
        else:
            return [None]
        
        return res


    def complete_db(self, args):
        """
        Complete the "db" command for whatever options available.
        """

        options = [option for (option,desc) in self.dbOptions]

        # show all the available options to set
        if len(args) == 0:
            return [o for o in options] + [None]

        # complete part of an existing option
        elif len(args) == 1:
            return [o + ' ' for o in options if o.startswith(args[0])] + [None]

        # if we've exhausted our options, return nothing
        else:
            return [None]
        
        return res


    def complete(self, text, state):
        """
        Generic readline completion entry point.
        """
        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()
        
        # show all commands
        if not line:
            return [c + ' ' for c in self.commands][state]
            
        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')
            
        # resolve command to the implementation functions (above)
        cmd = line[0].strip()
        if cmd in self.commands:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]
            
        results = [ c + ' ' for c in self.commands if c.startswith(cmd)] + [None]
        
        return results[state]


class IPCompleter(object):
    """
    Class used for tab completion of local IP (typically used for LHOST).
    """
    def __init__(self):
        pass
        
    """
    If blank line, fill in the local IP
    """
    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        if not line:
            ip = [commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]] + [None]
            return ip[state]
        else:
            return text[state]
            

class MSFPortCompleter(object):
    """
    Class used for tab completion of the default port (4444) for MSF payloads.
    """
    def __init__(self):
        pass
        
    """
    If blank line, fill in 4444
    """
    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        if not line:
            port = ["4444"] + [None]
            return port[state]
        else:
            return text[state]


class PathCompleter(object):
    """
    Class used for tab completion of files on the local path.
    """
    def __init__(self):
        pass

    def _listdir(self, root):
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
                for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_path(self, args):
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        return (self.complete_path(line) + [None])[state]

