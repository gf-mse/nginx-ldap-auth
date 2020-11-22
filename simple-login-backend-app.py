#!/usr/bin/python

## #!/bin/sh
## ''''which python  >/dev/null && exec python  "$0" "$@" # '''

# based on a 2014-2015 example by [Copyright (C)] Nginx, Inc.

# Example of an application working on port 9000
# To interact with nginx-ldap-auth-daemon this application
# 1) accepts GET  requests on /login and responds with a login form
# 2) accepts POST requests on /login, sets a cookie, and responds with redirect

import sys, os, signal, base64, cgi, argparse
if sys.version_info.major == 2:
    from urlparse import urlparse
    from Cookie import BaseCookie
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
elif sys.version_info.major == 3:
    from urllib.parse import urlparse
    from http.cookies import BaseCookie
    from http.server import HTTPServer, BaseHTTPRequestHandler

## Listen = ('localhost', 9000)

import threading
if sys.version_info.major == 2:
    from SocketServer import ThreadingMixIn
elif sys.version_info.major == 3:
    from socketserver import ThreadingMixIn


def ensure_bytes(data):
    return data if sys.version_info.major == 2 else data.encode("utf-8")


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class AppHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        url = urlparse(self.path)

        if 0:
            if url.path.startswith("/login"):
                return self.auth_form()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(ensure_bytes('Hello, world! Requested URL: ' + self.path + '\n'))

        # all we do on any get is send the authentication form
        return self.auth_form()



    # send login form html
    def auth_form(self, target = None):

        # try to get target location from header
        if target == None:
            target = self.headers.get('X-Target')

        # form cannot be generated if target is unknown
        if target == None:
            self.log_error('target url is not passed')
            self.send_response(500)
            return

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
    <title>Auth form example</title>
  </head>
  <body>
    <form action="/login" method="post">
      <table>
        <tr>
          <td>Username: <input type="text" name="username"/></td>
        <tr>
          <td>Password: <input type="password" name="password"/></td>
        <tr>
          <td><input type="submit" value="Login"></td>
      </table>
        <input type="hidden" name="target" value="TARGET">
    </form>
  </body>
</html>"""

        self.send_response(200)
        self.end_headers()
        
        # fix the hidden form falue
        self.wfile.write(ensure_bytes(html.replace('TARGET', target)))


    # processes posted form and sets the cookie with login/password
    def do_POST(self):

        # prepare arguments for cgi module to read posted form
        env = {'REQUEST_METHOD':'POST',
               'CONTENT_TYPE': self.headers['Content-Type'],}

        # read the form contents
        form = cgi.FieldStorage(fp = self.rfile, headers = self.headers,
                                environ = env)

        # extract required fields
        user = form.getvalue('username')
        passwd = form.getvalue('password')
        target = form.getvalue('target')

        if user != None and passwd != None and target != None:

            # form is filled, set the cookie and redirect to target
            # so that auth daemon will be able to use information from cookie

            self.send_response(302)

            # WARNING WARNING WARNING
            #
            # base64 is just an example method that allows to pack data into
            # a cookie. You definitely want to perform some encryption here
            # and share a key with auth daemon that extracts this information
            #
            # WARNING WARNING WARNING
            enc = base64.b64encode(ensure_bytes(user + ':' + passwd))
            # we shall betetr decode all of it at once
            if 0:
                if sys.version_info.major == 3:
                    enc = enc.decode()

            ## self.send_header('Set-Cookie', b'nginxauth=' + enc + b'; httponly')
            ## cookie_text = self._cookie_name + enc + b'; httponly'
            cookie_text = "{}={}; httponly".format( self._cookie_name, enc )
            if self._set_secure_cookie:
                # [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Secure ]
                ## cookie_text += b'; secure'
                cookie_text += '; secure'

            self.log_message( "setting a cookie for user '%s' ... ", user )

            cookie_bytes = ensure_bytes( cookie_text )
            self.send_header( 'Set-Cookie', cookie_bytes )

            self.send_header( 'Location', target )
            self.end_headers()

            return

        # else ..
        self.log_error( "some form fields are not provided // user: '%s' ; target: '%s'", user, target )
        # nb: if the target field is empty, this will lead to an error 500 at the next step
        self.auth_form(target)


    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        sys.stdout.write("%s - - [%s] %s\n" % (addr,
                         self.log_date_time_string(), format % args))

    def log_error(self, format, *args):
        self.log_message(format, *args)


    def flush_log_buffer(self):
        sys.stdout.flush()

    def send_error( self, status_code, str_message, *args, **kwargs ):
        
        BaseHTTPRequestHandler.send_error( self, status_code, str_message, *args, **kwargs )
        self.flush_log_buffer()

    def end_headers(self):
        
        BaseHTTPRequestHandler.end_headers( self )
        self.flush_log_buffer()



def exit_handler(signal, frame):
    sys.exit(0)

def parse_argv():

    parser = argparse.ArgumentParser(
        description="""Simple Nginx LDAP authentication helper.""")
    
    # Group for listen options:
    group = parser.add_argument_group("Listen options")
    group.add_argument('--host',  metavar="hostname",
        default="localhost", help="host to bind (Default: localhost)")
    group.add_argument('-p', '--port', metavar="port", type=int,
        default=9000, help="port to bind (Default: 9000)")

    group = parser.add_argument_group("Cookie options")
    group.add_argument('--cookie-name', dest = 'cookie_name', metavar="cookie name", action='store',
        default='nginxauth', help="authentication cookie name")
    group.add_argument('--secure-cookie', '--cookie-demand-https', dest = 'want_secure_cookie', action='store_true',
        default=None, help="insist for a secure connection (https) for the cookie")


    group = parser.add_argument_group(title="Command line arguments")
    group.add_argument( 'argv', metavar='arg'
                      ## , dest='argv' // 'dest supplied twice for positional argument'
                      , action='store', nargs='*'
                      , help="say 'run' or 'go' to start serving connections"
                      )

    args = parser.parse_args()
    
    return args, parser
    

if __name__ == '__main__':

    args, parser = parse_argv()
    if not args.argv:
        parser.print_help()
        sys.exit(2)

    # else ...
    global Listen
    Listen = (args.host, args.port)

    #
    # AppHandler options, if any
    #

    ## AppHandler._cookie_name        = ensure_bytes( args.cookie_name )
    AppHandler._cookie_name        = args.cookie_name
    AppHandler._set_secure_cookie  = args.want_secure_cookie

    server = AuthHTTPServer(Listen, AppHandler)
    
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    
    server.serve_forever()
