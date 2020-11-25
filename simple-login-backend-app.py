#!/usr/bin/python

## #!/bin/sh
## ''''which python  >/dev/null && exec python  "$0" "$@" # '''

from __future__ import print_function

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


## from redis_wrapper import CustomRedisMixin
## from redis_wrapper import CustomRedisMixin, ensure_bytes
from redis_wrapper import CustomRedisMixin, ensure_bytes, KEY_HISTORY_MAXLEN


## # let us use simplejson for serializing
## from json import ( dumps as json_dumps, loads as json_loads )

APP_VERSION = '1.0 fernet-json'

##  def ensure_bytes(data):
##      return data if sys.version_info.major == 2 else data.encode("utf-8")


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class AppHandler( BaseHTTPRequestHandler, CustomRedisMixin ):

    # print exceptions to stderr
    _debug_mode = None

    # print request headers
    do_log_headers = None

    def do_GET(self):

        self.log_request_headers() # shows nothing if not told to

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
    <title>Authentication</title>
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

        self.log_request_headers() # shows nothing if not told to

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

        cookie_headers = []

        if user != None and passwd != None and target != None:

            # let's encode the received data
            try:
                ## # WARNING WARNING WARNING
                ## enc = base64.b64encode(ensure_bytes(user + ':' + passwd))
                data = dict( user=user, passwd=passwd, httponly = True )
                if self._set_secure_cookie:
                    data['secure'] = True
                # could do the same for max-age, 
                # although we shall make it arrive from the form 
                
                pairs = self.get_set_enc_keys()
                pairs.sort() # ascending -- recent last
                
                if not pairs:
                    self.fail( 418, "internal error"
                             , log_message = "problem: no valid encryption keys found in redis" )
                    return True
                    
                # else ...
                storage_key, encryption_key = pairs[-1]
                cookie_data = self.encrypt_cookie( data, encryption_key )

                self.log_message( "cooking headers for user '%s' ... ", user )

                headers_text = self.format_cookie( self._cookie_name, cookie_data
                                                 , secure = data.get('secure')
                                                 , max_age = data.get('max-age')
                                                 , header='', sep='\0' )

                cookie_headers = [ h.lstrip() for h in headers_text.split('\0') ]

            except:
                
                self.fail( 418, "internal error", log_message = "failed at encoding stage" )
                if self._debug_mode :
                    raise
                # else ...
                return True

            # form is filled, set the cookie and redirect to target
            # so that auth daemon will be able to use information from cookie

            self.send_response(302)

            for h in cookie_headers:
                cookie_bytes = ensure_bytes( h )
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


    def log_request_headers(self):
        
        if self.do_log_headers:
            
            self.log_request()
            for key_val in self.headers.items():
                h,v = key_val
                # mask any headers that can contain authentication data
                if h.lower() in ('authorization', 'cookie'):
                    self.log_message("[h]: %s: ***", h)
                else:
                    self.log_message("[h]: %s: %s", *key_val)


    def flush_log_buffer(self):
        sys.stdout.flush()

    def send_error( self, status_code, str_message, *args, **kwargs ):
        
        BaseHTTPRequestHandler.send_error( self, status_code, str_message, *args, **kwargs )
        self.flush_log_buffer()

    def fail( self, status, message, log_message, *args, **kwargs ):

        self.log_error( log_message )
        self.send_error( status, message, *args, **kwargs )


    def end_headers(self):
        
        BaseHTTPRequestHandler.end_headers( self )
        self.flush_log_buffer()



def exit_handler(signal, frame):
    sys.exit(0)

def parse_argv():

    parser = argparse.ArgumentParser(
        description="""Simple Nginx LDAP authentication helper.""")
    
    group = parser.add_argument_group("Version info")
    group.add_argument('--version',  dest='print_version', action='store_true', # metavar="...",
        default=None, help="print the version and exit")

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

    # redis key options:
    group = parser.add_argument_group("Redis / key options")
    group.add_argument('--redis-server',  metavar="redis-server", dest='redis_server', action='store',
        default="localhost", help="redis server (Default: localhost)")
    group.add_argument('--redis-port', metavar="redis-port", dest='redis_port', action='store', type=int, 
        default=6379, help="redis server port (Default: 6379)")
    group.add_argument('--redis-key-history-length',  metavar="key-history-maxdays", dest='key_history_maxdays', action='store', type=int,
        default=KEY_HISTORY_MAXLEN, help="keep encryption keys for this many days; default: " + str(KEY_HISTORY_MAXLEN) )


    # debug options (show headers, etc)
    group = parser.add_argument_group("Debug options")
    group.add_argument('--debug-mode',  dest='_debug_mode', action='store_true', # metavar="...",
        default=None, help="log exceptions to stderr")
    group.add_argument('--log-headers',  dest='log_headers', action='store_true', # metavar="...",
        default=None, help="log request headers (to stderr)")

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
    
    if args.print_version:
        print( APP_VERSION, file=sys.stdout )
        sys.exit(1)
    
    if not args.argv:
        parser.print_help()
        sys.exit(2)

    # else ...
    global Listen
    Listen = (args.host, args.port)

    #
    # AppHandler options, if any
    #

    redis_key_params = {
        # redis host
        'host' : args.redis_server
        # redis port ( 6379 is redis default )
    ,   'port' : args.redis_port
        # how many days ( or, to be more accurate, _distinct keys_ ) to keep
    ,   'keep_days' : args.key_history_maxdays
    }
    AppHandler.set_redis_params( redis_key_params )

    ## AppHandler._cookie_name        = ensure_bytes( args.cookie_name )
    AppHandler._cookie_name        = args.cookie_name
    AppHandler._set_secure_cookie  = args.want_secure_cookie

    AppHandler._debug_mode        = args._debug_mode
    AppHandler.do_log_headers     = args.log_headers

    server = AuthHTTPServer(Listen, AppHandler)
    
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    
    server.serve_forever()
