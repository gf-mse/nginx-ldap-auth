#!/usr/bin/python
## #!/bin/sh
## ''''[ -z $LOG ] && export LOG=/dev/stdout # '''
## ''''which python  >/dev/null && exec python  -u "$0" "$@" >> $LOG 2>&1 # '''

# Copyright (C) 2014-2015 Nginx, Inc.
# // some additions  ( cookie encryption, etc )  by gf-mse  

from __future__ import print_function

import sys, os, signal, base64, ldap, argparse
if sys.version_info.major == 2:
    from Cookie import BaseCookie
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
elif sys.version_info.major == 3:
    from http.cookies import BaseCookie
    from http.server import HTTPServer, BaseHTTPRequestHandler

if not hasattr(__builtins__, "basestring"): basestring = (str, bytes)

# -----------------------------------------------------------------------------
# here we are using cryptography.fernet to encrypt the cookies,
# and redis db to share keys between the authentication server and the login backend.
#
# ( we could have implemented both in a single process 
#   and thus keep the keys within the same process address space, 
#   but instead we assume that hte main protected resource 
#   does not have access to it -- e.g. sits inside a container )
#


##  # let us use simplejson for serializing
##  from json import ( dumps as json_dumps, loads as json_loads )

from redis_wrapper import CustomRedisMixin, ensure_bytes, KEY_HISTORY_MAXLEN

#
# on encryption keys:
#
#  - they are stored in a Redis database, 
#    which is expected to be local 
#    (db connection is not encrypted) 
#    and isolated from the backend
#  - in the code, they may be called "storage values"
#    as opposed to "storage keys", which are originally just dates
#  - we are trying to issue a new key on each day 
#    where we have at least one request
#  - if a cookie was encrypted not longer than "max days" ago,
#    we are trying to re-encrypt it with a most recent key
#    and return back to the client
#  - finally, we may add a "max-age" parameter 
#    to advise the client to dispose the cookie after some timeout
#

#
# on passing cookies:
#
# - our cookie {cookiename} _may_ be accompanied by {cookiename_attrs}
#   // it would probably be more secure to pack them in a single json, though
#

APP_VERSION = '1.0 fernet'

## DAY_IN_SECONDS = 24 * 60 * 60.0
## KEY_HISTORY_MAXLEN = 14 + 3  # two weeks and a little something


# -----------------------------------------------------------------------------

#Listen = ('localhost', 8888)
#Listen = "/tmp/auth.sock"    # Also uncomment lines in 'Requests are
                              # processed with UNIX sockets' section below

# -----------------------------------------------------------------------------
# Different request processing models: select one
# -----------------------------------------------------------------------------
# Requests are processed in separate thread
import threading
if sys.version_info.major == 2:
    from SocketServer import ThreadingMixIn
elif sys.version_info.major == 3:
    from socketserver import ThreadingMixIn

class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass
# -----------------------------------------------------------------------------
# Requests are processed in separate process
#from SocketServer import ForkingMixIn
#class AuthHTTPServer(ForkingMixIn, HTTPServer):
#    pass
# -----------------------------------------------------------------------------
# Requests are processed with UNIX sockets
#import threading
#from SocketServer import ThreadingUnixStreamServer
#class AuthHTTPServer(ThreadingUnixStreamServer, HTTPServer):
#    pass
# -----------------------------------------------------------------------------


## def ensure_bytes(data):
##     return data if sys.version_info.major == 2 else data.encode("utf-8")
if 0:
    if sys.version_info.major == 2:
        def ensure_bytes(data):
            return data
    else:
        def ensure_bytes(data):
            if not isinstance( data, bytes ):
                result = data.encode("utf-8")
            else:
                result = data
            return result


class AuthHandler(BaseHTTPRequestHandler, CustomRedisMixin):

    do_log_headers = None
    use_cookie_only = None # ignore 'authorization' header

    # -------------------------------------------------------------------------

    # Return True if request is processed and response sent, otherwise False
    # Set ctx['user'] and ctx['pass'] for authentication
    def do_GET(self):

        ctx = self.ctx
        ctx['action'] = 'log request / headers'
        self.log_request_headers() # shows nothing if not told to

        ctx['action'] = 'input parameters check'
        for k, v in self.get_params().items():
            ctx[k] = self.headers.get(v[0], v[1])
            if ctx[k] == None:
                self.auth_failed(ctx, 'required "%s" header was not passed' % k)
                return True

        ctx['action'] = 'performing authorization'
        auth_header = None # default
        if not self.use_cookie_only:
            auth_header = self.headers.get('Authorization')
        auth_cookie = self.get_cookie(ctx['cookiename'])

        if auth_cookie != None and auth_cookie != '':
            auth_header = "Basic " + auth_cookie
            self.log_message("using username/password from cookie %s" %
                             ctx['cookiename'])
        else:
            self.log_message("using username/password from authorization header")

        if auth_header is None or not auth_header.lower().startswith('basic '):

            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            return True

        ctx['action'] = 'decoding credentials'

        try:
            ## auth_decoded = base64.b64decode(auth_header[6:])
            pairs = self.get_set_enc_keys()
            pairs.sort( reverse = True ) # recent first
            decoded = self.decrypt_cookie( auth_header[6:], pairs, sort=False )
            if decoded is None:
                self.log_error("none of %s known keys could decrypt the supplied credentials", len(pairs))
                self.auth_failed(ctx)
                return True                
            # else ...
            ## storage_key, auth_decoded = decoded
            storage_key, data = decoded # assume a json-decoded object

            # the list is not empty, since we have just successfully used it for decoding
            recent_pair = pairs[0]
            recent_storage_key, recent_enc_key = recent_pair
            if storage_key != recent_storage_key :
                self.log_message("re-encrypting data of '%s' with '%s' ...", storage_key, recent_storage_key )
                # re-encrypt the data with the most recent key ..
                encrypted = self.encrypt_cookie( data, recent_enc_key )
                ## new_cookie_text = "{}={}; httponly".format( self._cookie_name, enc )
                
                self.log_message( "cooking headers ..." )
                headers_text = self.format_cookie( ctx['cookiename'], encrypted
                                                 , secure = data.get('secure')
                                                 , max_age = data.get('max-age')
                                                 , header='', sep='\0' )
                headers_list = [ h.lstrip() for h in headers_text.split('\0') ]

                ctx['set-cookies'] = headers_list # could be empty

            ## if sys.version_info.major == 3: auth_decoded = auth_decoded.decode("utf-8")
            ## user, passwd = auth_decoded.split(':', 1)

            user = data.get('user')
            passwd = data.get('passwd')

        except:
            self.auth_failed(ctx)
            return True

        if not user or not passwd:
            self.log_error("empty username ('%s') or password", user)
            self.auth_failed(ctx)
            return True

        ctx['user'] = user
        ctx['pass'] = passwd

        # Continue request processing
        return False

    def get_cookie(self, name):
        cookies = self.headers.get('Cookie')
        if cookies:
            authcookie = BaseCookie(cookies).get(name)
            if authcookie:
                return authcookie.value
            else:
                return None
        else:
            return None


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
            
            

    # Log the error and complete the request with appropriate status
    def auth_failed(self, ctx, errmsg = None):

        msg = 'Error while ' + ctx['action']
        if errmsg:
            msg += ': ' + errmsg

        ex, value, trace = sys.exc_info()

        if ex != None:
            msg += ": " + str(value)

        if ctx.get('url'):
            msg += ', server="%s"' % ctx['url']

        if ctx.get('user'):
            msg += ', login="%s"' % ctx['user']

        self.log_error(msg)
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

        # help debugging
        self.flush_log_buffer()

    def get_params(self):
        return {}

    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
            ## addr = self.address_string()
        else:
            addr = "-"

        remote = self.headers.get('x-forwarded-for', '-')

        if not hasattr(self, 'ctx'):
            user = '-'
        else:
            ## user = self.ctx['user']
            user = '(%s)' % ( self.ctx['user'], )


        sys.stdout.write("%s - %s %s [%s] %s\n" % (addr, remote, user, self.log_date_time_string()
                                                  , format % args))

    def flush_log_buffer(self):
        sys.stdout.flush()

    def log_error(self, format, *args):
        self.log_message(format, *args)

    def send_error( self, status_code, str_message, *args, **kwargs ):
        
        BaseHTTPRequestHandler.send_error( self, status_code, str_message, *args, **kwargs )
        self.flush_log_buffer()

    def end_headers(self):
        
        BaseHTTPRequestHandler.end_headers( self )
        self.flush_log_buffer()
        


# Verify username/password against LDAP server
class LDAPAuthHandler(AuthHandler):
    # Parameters to put into self.ctx from the HTTP header of auth request
    params =  {
             # parameter      header         default
             'realm': ('X-Ldap-Realm', 'Restricted'),
             'url': ('X-Ldap-URL', None),
             'starttls': ('X-Ldap-Starttls', 'false'),
             'disable_referrals': ('X-Ldap-DisableReferrals', 'false'),
             'basedn': ('X-Ldap-BaseDN', None),
             'template': ('X-Ldap-Template', '(cn=%(username)s)'),
             'binddn': ('X-Ldap-BindDN', ''),
             'bindpasswd': ('X-Ldap-BindPass', ''),
             'cookiename': ('X-CookieName', '')
        }

    do_send_username = None

    @classmethod
    def set_params(cls, params):
        cls.params = params
        ## # allow missing fields (but risk fields mistyped later)
        # cls.params.update(params)

    def get_params(self):
        return self.params


    # GET handler for the authentication request
    def do_GET(self):

        ## ctx = dict()
        ## self.ctx = ctx
        ctx = getattr( self, 'ctx', dict() )
        self.ctx = ctx

        ctx['action'] = 'initializing basic auth handler'
        ctx['user'] = '-'

        if AuthHandler.do_GET(self):
            # request already processed
            self.flush_log_buffer()
            return True

        ctx['action'] = 'empty password check'
        if not ctx['pass']:
            self.auth_failed(ctx, 'attempt to use empty password')
            return True

        try:
            # check that uri and baseDn are set
            # either from cli or a request
            if not ctx['url']:
                self.log_message('LDAP URL is not set!')
                return True
            if not ctx['basedn']:
                self.log_message('LDAP baseDN is not set!')
                return True

            ctx['action'] = 'initializing LDAP connection'
            ldap_obj = ldap.initialize(ctx['url']);

            # Python-ldap module documentation advises to always
            # explicitely set the LDAP version to use after running
            # initialize() and recommends using LDAPv3. (LDAPv2 is
            # deprecated since 2003 as per RFC3494)
            #
            # Also, the STARTTLS extension requires the
            # use of LDAPv3 (RFC2830).
            ldap_obj.protocol_version=ldap.VERSION3

            # Establish a STARTTLS connection if required by the
            # headers.
            if ctx['starttls'] == 'true':
                ldap_obj.start_tls_s()

            # See https://www.python-ldap.org/en/latest/faq.html
            if ctx['disable_referrals'] == 'true':
                ldap_obj.set_option(ldap.OPT_REFERRALS, 0)

            ctx['action'] = 'binding as search user'
            ldap_obj.bind_s(ctx['binddn'], ctx['bindpasswd'], ldap.AUTH_SIMPLE)

            ctx['action'] = 'preparing search filter'
            searchfilter = ctx['template'] % { 'username': ctx['user'] }

            self.log_message(('searching on server "%s" with base dn ' + \
                              '"%s" with filter "%s"') %
                              (ctx['url'], ctx['basedn'], searchfilter))

            ctx['action'] = 'running search query'
            results = ldap_obj.search_s(ctx['basedn'], ldap.SCOPE_SUBTREE,
                                          searchfilter, ['objectclass'], 1)

            ctx['action'] = 'verifying search query results'

            nres = len(results)

            if nres < 1:
                self.auth_failed(ctx, 'no objects found')
                return True

            if nres > 1:
                self.log_message("note: filter match multiple objects: %d, using first" % nres)

            user_entry = results[0]
            ldap_dn = user_entry[0]

            if ldap_dn == None:
                self.auth_failed(ctx, 'matched object has no dn')
                return True

            self.log_message('attempting to bind using dn "%s"' % (ldap_dn))

            ctx['action'] = 'binding as an existing user "%s"' % ldap_dn

            ldap_obj.bind_s(ldap_dn, ctx['pass'], ldap.AUTH_SIMPLE)

            self.log_message('Auth OK for user "%s"' % (ctx['user']))
            
            ## # we will use it in a child handler as a control check for unsuccessful authentication
            ## ctx['username'] = ctx['user']

            # Successfully authenticated user
            self.send_response(200)
            
            # send back the re-encrypted cookie, if any )
            c_headers = ctx.get('set-cookies', [])
            for h in c_headers:
                cookie_bytes = ensure_bytes( h )
                self.send_header( 'Set-Cookie', cookie_bytes )

            # also send the username, if requested
            x_username = self.do_send_username
            if x_username :
                ## self.send_header( x_username,  ldap_dn)
                self.send_header( x_username,  ctx['user'])

            self.end_headers()

        except:
            self.auth_failed(ctx)
            return True


# actually, this is needed for Unix sockets only
def exit_handler(signal, frame):
    global Listen

    if isinstance(Listen, basestring):
        try:
            os.unlink(Listen)
        except:
            ex, value, trace = sys.exc_info()
            sys.stderr.write('Failed to remove socket "%s": %s\n' %
                             (Listen, str(value)))
            sys.stderr.flush()
    sys.exit(0)


# -----------------------------------------------------------------------------

def normalize_header( header_name ):
    """ be nice and prepend a header name with an 'x-' """

    # be standard conforming -- don't create nonstandard headers
    if not header_name.lower().startswith('x-'):
        # adhere to the original style  
        if header_name[:1].isupper():
            header_name += 'X-'
            # send_username = send_username.title()
        else:
            header_name += 'x-'
    
    return header_name



if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(
        description="""Simple Nginx LDAP authentication helper.""")

    # debug options (show headers, etc)
    group = parser.add_argument_group("Debug options")
    group.add_argument('--version',  dest='print_version', action='store_true', # metavar="...",
        default=None, help="print the version and exit")
    group.add_argument('--log-headers',  dest='log_headers', action='store_true', # metavar="...",
        default=None, help="log request headers (to stderr)")
    
    # Group for listen options:
    group = parser.add_argument_group("Listen options")
    group.add_argument('--host',  metavar="hostname",
        default="localhost", help="host to bind (Default: localhost)")
    group.add_argument('-p', '--port', metavar="port", type=int,
        default=8888, help="port to bind (Default: 8888)")
    
    # ldap options:
    group = ldap_group = parser.add_argument_group(title="LDAP options")
    group.add_argument('-u', '--url', metavar="URL",
        default="ldap://localhost:389",
        help=("LDAP URI to query (Default: ldap://localhost:389)"))
    group.add_argument('-s', '--starttls', metavar="starttls",
        default="false",
        help=("Establish a STARTTLS protected session (Default: false)"))
    group.add_argument('--disable-referrals', metavar="disable_referrals",
        default="false",
        help=("Sets ldap.OPT_REFERRALS to zero (Default: false)"))
    group.add_argument('-b', metavar="baseDn", dest="basedn", default='',
        help="LDAP base dn (Default: unset)")
    group.add_argument('-D', metavar="bindDn", dest="binddn", default='',
        help="LDAP bind DN (Default: anonymous)")
    group.add_argument('-w', metavar="passwd", dest="bindpw", default='',
        help="LDAP password for the bind DN (Default: unset)")
    group.add_argument('-f', '--filter', metavar='filter',
        default='(cn=%(username)s)',
        help="LDAP filter (Default: cn=%%(username)s)")

    # http options:
    group = parser.add_argument_group(title="HTTP options")
    group.add_argument('-R', '--realm', metavar='"Restricted Area"',
        default="Restricted", help='HTTP auth realm (Default: "Restricted")')
    ## group = parser.add_argument_group("Cookie options")
    ## group.add_argument('--cookie-name', dest = 'cookie_name', metavar="cookie name", action='store'
    ##     default='nginxauth', help="authentication cookie name")
    group.add_argument('-c', '--cookie-name', '--cookie', metavar="cookiename", dest = 'cookie_name', 
        default="", help="HTTP cookie name to set in (Default: unset)")
    # this deals more with authentication, so we list it here, but logically assign to LDAP options:
    ldap_group.add_argument('--cookie-only', '--ignore-auth-header', dest = 'auth_cookie_only', action = 'store_true',
        default=None, help="Ignore authorization header and accept only (encrypted) authentication cookie")
    group.add_argument('--send-username-header', dest='send_username', action='store', metavar="x-username",
        default='', help="if set -- return back a username under a given header (e.g. 'x-username') ")
    #   ^^^ nb: this will send the (first) username that is found on the LDAP server after applying the filter,
    #           that is -- not necessarily the username that was sent;
    #           in other words, if 'abcdef' is a unique user prefix with the only match 'abcdef123',
    #           then 'abcdef*:correct-password' and a filter '(cn=%(username)s)' would succeed and return 'abcdef123'


    # redis key options:
    group = parser.add_argument_group("Redis / key options")
    group.add_argument('--redis-server',  metavar="redis-server", dest='redis_server', action='store',
        default="localhost", help="redis server (Default: localhost)")
    group.add_argument('--redis-port', metavar="redis-port", dest='redis_port', action='store', type=int, 
        default=6379, help="redis server port (Default: 6379)")
    group.add_argument('--redis-key-history-length',  metavar="key-history-maxdays", dest='key_history_maxdays', action='store', type=int,
        default=KEY_HISTORY_MAXLEN, help="keep encryption keys for this many days; default: " + str(KEY_HISTORY_MAXLEN) )


    group = parser.add_argument_group(title="Command line arguments")
    group.add_argument( 'argv', metavar='arg'
                      ## , dest='argv' // 'dest supplied twice for positional argument'
                      , action='store', nargs='*'
                      , help="say 'run' or 'go' to start serving connections"
                      )

    args = parser.parse_args()
    
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
    # AuthHandler options
    #

    AuthHandler.use_cookie_only = args.auth_cookie_only

    redis_key_params = {
        # redis host
        'host' : args.redis_server
        # redis port ( 6379 is redis default )
    ,   'port' : args.redis_port
        # how many days ( or, to be more accurate, _distinct keys_ ) to keep
    ,   'keep_days' : args.key_history_maxdays
    }
    AuthHandler.set_redis_params( redis_key_params )

    AuthHandler.do_log_headers = args.log_headers

    #
    # LDAPAuthHandler options
    #

    auth_params = {
             'realm': ('X-Ldap-Realm', args.realm),
             'url': ('X-Ldap-URL', args.url),
             'starttls': ('X-Ldap-Starttls', args.starttls),
             'disable_referrals': ('X-Ldap-DisableReferrals', args.disable_referrals),
             'basedn': ('X-Ldap-BaseDN', args.basedn),
             'template': ('X-Ldap-Template', args.filter),
             'binddn': ('X-Ldap-BindDN', args.binddn),
             'bindpasswd': ('X-Ldap-BindPass', args.bindpw),
             ## 'cookiename': ('X-CookieName', args.cookie)
             'cookiename': ('X-CookieName', args.cookie_name)
    }
    LDAPAuthHandler.set_params(auth_params)
    ## LDAPAuthHandler._log_headers = args.log_headers
    ## AuthHandler.do_log_headers = args.log_headers
    ## LDAPAuthHandler.do_send_username = None
    send_username = args.send_username.strip()
    if send_username:
        send_username = normalize_header( send_username )
        LDAPAuthHandler.do_send_username = send_username

    server = AuthHTTPServer(Listen, LDAPAuthHandler)

    # unlink the Unix socket if this is enabled 
    # // the latter commented out by default, 
    # // see 'Listen' at the top of the file
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    # nb: we have also redefined default .log_message() behaviour from writing to stderr ..
    # [ https://docs.python.org/3/library/http.server.html#http.server.BaseHTTPRequestHandler.log_message ]
    # .. to writing to stdout ( and it is probably fully buffered )
    sys.stdout.write("Start listening on %s:%d...\n" % Listen)
    sys.stdout.flush()

    server.serve_forever()

