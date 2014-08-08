
"""

HTTP-related methods.

Includes: 

    RequestHandler()    - a customized handler to serve out /tmp/pillage/
    VeilHTTPServer()    - a small webserver for Veil that can run HTTP or HTTPS

"""


import BaseHTTPServer, threading, ssl, os
from SimpleHTTPServer import SimpleHTTPRequestHandler

# Prepend /tmp/pillage/ to any served file path- not the best way
# to do this (i.e. nesting) but it's quick and easy and all we need
# to host out of the directory we want
class RequestHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        return "/tmp/pillage/" + path


class VeilHTTPServer(threading.Thread):
    """
    Version of a simple HTTP[S] Server with specifiable port and
    SSL cert. Defaults to HTTP is no cert is specified.

    Uses RequestHandler to serve a custom directory.
    """

    def __init__(self, port=80, cert=''):

        threading.Thread.__init__(self)

        # remove the temp directory, recreate it and build a blank index.html
        cleanCmd = "rm -rf /tmp/pillage/ && mkdir /tmp/pillage/ && touch /tmp/pillage/index.html"
        os.system(cleanCmd)

        self.server = BaseHTTPServer.HTTPServer(('0.0.0.0', port), RequestHandler)
        self.serverType = "HTTP"

        # wrap it all up in SSL if a cert is specified
        if cert != "":
            self.serverType = "HTTPS"
            self.server.socket = ssl.wrap_socket(self.server.socket, certfile=cert, server_side=True)

    def run(self):

        print "\n [*] Setting up "+self.serverType+" server..."
        try: self.server.serve_forever()
        except: pass

    def shutdown(self):

        print "\n [*] Killing "+self.serverType+" server..."

        # shut down the server/socket
        self.server.shutdown()
        self.server.socket.close()
        self.server.server_close()
        self._Thread__stop()

        # make sure all the threads are killed
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except:
                    pass

