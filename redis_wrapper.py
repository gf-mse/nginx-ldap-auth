#!/usr/bin/python

"""
    sharing keys between nginx-ldap-auth-daemon.py 
    and simple-login-backend.py through a redis server
    
    // nb: put backend out of the same process space -- e.g. inside a container!
"""

from __future__ import print_function

## import re
# import os
import sys
## import time
from time import ( strftime, strptime, localtime, mktime, time as now ) 
# // mktime(strptime(strftime('%F %T', localtime()), '%Y-%m-%d %H:%M:%S')) ~ strftime('%s')

# let us use simplejson for serializing
from json import ( dumps as json_dumps, loads as json_loads )

if sys.version_info.major == 2:
    from Cookie import BaseCookie
elif sys.version_info.major == 3:
    from http.cookies import BaseCookie


have_prerequisites = True # assume the best
try:
    from cryptography.fernet import Fernet, InvalidToken # wrong key or data
    ## FernetExceptions = ( InvalidToken, ) # also TypeError for non-keys
except ImportError as e:
    print( "install pyca/cryptography: 'pip install cryptography'", file=sys.stderr )
    have_prerequisites = False

try:
    from redis import Redis
except ImportError as e:
    print( "install redis-py: 'pip install redis'", file=sys.stderr )
    have_prerequisites = False

if not have_prerequisites:
    sys.exit(2)

## from cryptography.fernet import Fernet, InvalidToken # wrong key or data
## from redis import Redis

DAY_IN_SECONDS = 24 * 60 * 60.0
DAYS = DAY_IN_SECONDS

KEY_HISTORY_MAXLEN = 14 + 3  # two weeks and a little something


# --------------------------------------------------------------------------------
# not that it absolutely must belong here, it is just easier to share this code

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


# --------------------------------------------------------------------------------

class RedisWrapper(object):
    """
        new_key = rw.new_key()
        if new_key not in rw.keys():
            value = f.generate_key()
            added = rw.add( new_key, value )
            if not added:
                new_value = rw.get( new_key )
            # or 
            new_value = rw.try_add( new_key, value )
    """

    # redis key prefix -- used e.g. in Redis::keys('<mask>')
    # // nb: make a longer/unique pattern if using redis db for something else as well
    KEY_PREFIX = 'fn-'

    # date-compatible key template ; 
    # used both to create new keys and parse the old ones, if needed
    # // 'fn' stands for 'pyca/cryptography/fernet' )
    ## KEY_TEMPLATE  = KEY_PREFIX + "%F" # %F ~ %Y-%m-%d
    KEY_TEMPLATE  = KEY_PREFIX + "%Y-%m-%d" # somehow strptime() does not like '%F' ...
    
    # use this with Redis::keys()
    KEY_MASK      = KEY_PREFIX + '*'
    
    @classmethod
    def _make_new_redis_key(cls, timestamp = None):
        """
            make a new key based on a given or current timestamp
        """

        if timestamp is None:
            key = strftime( cls.KEY_TEMPLATE )
        else:
            key = strftime( cls.KEY_TEMPLATE, localtime(timestamp) )

        # shall be a floating-point value
        return key

    # a shorter alias
    new_key = _make_new_redis_key


    def __init__(self, host = 'localhost', port = 6379):
        
        self._host = host
        self._port = port
        
        self._db = Redis( host = host
                        , port = port
                        # // if you want to keep it on the same server,
                        # // then protect redis.conf from reading, etc
                        #, password='password'
                        )


    def get_keys( self, sort_keys = False, reverse = False ):
        """ retrieve existing keys from Redis """
        
        keys = self._db.keys( self.KEY_MASK )

        if sort_keys:
            if callable( sort_keys ):
                keys.sort( key=sort_keys, reverse=reverse )
            else:
                keys.sort( reverse=reverse )

        return keys

    # a shorter alias
    keys = get_keys


    def get_value( self, key, default = None ):
        
        result = self._db.get(key)
        if result is None:
            result = default
            
        return result
        
    # a shorter alias
    get = get_value
    
    
    def add_value( self, key, value ):
        """
            add the value _if it is not set already_ ;     

            this returns True if the value was added,
            or False otherwise
        """
        
        result = self._db.set( key, value, nx=True )
        if result is None:
            result = False
        
        return result
        
    # a shorter alias
    add = add_value


    def try_add( self, key, value ):
        """
            attempts an .add_value() /and returns it/,
            then does a .get_value() if that fails / and returns that then / ;  
            
            this is not atomic, though, 
            so a deletion happening in between
            can result in .get_value() returning None ;
            
            however, trying a .get_value() first
            and then attempting to add leads to another race condition,
            which is probably even less preferable
            ( getting no value in the first case vs 
              having two different values at two clients, 
              if they don't check the .add() result 
            )
        """

        result = self.add_value(key, value)
        if result:
            ret = value
        else:
            ret = self.get_value( key, None )

        # could still return a None under race
        return ret


    def delete_key( self, key ):
        """
            returns True if the key had an associated value
        """

        result = self._db.delete( key )
        if result <= 0 :
            result = False
        
        return bool(result)


    # a shorter alias
    delete = delete_key
        

    def expire_keys( self, timeout_seconds, time_point = None  ):
        """
            delete keys that are too old -- older than ( time_point - timeout )
        """

        if time_point is None:
            time_point = now()

        # here we assume that there's a reasonable amount of the keys in the database
        text_keys = self.get_keys()
        # NB: for shared redis environments, we may have to either make the prefix unique,
        #     or to handle conversion ValueError exceptions raised by strptime() invocation below
        timestamps = [ mktime(strptime(key_text, self.KEY_TEMPLATE)) for key_text in text_keys ]

        zipped = zip( text_keys, timestamps )

        margin = time_point - timeout_seconds
        ## to_delete = [ pair[0] for pair in zipped if pair[1] < margin ]
        ## filtered = [ pair[0] for pair in zipped if pair[1] >= margin ]
        to_delete = []
        filtered = []
        for pair in zipped:
            if pair[1] < margin :
                to_delete.append( pair[0] )
            else:
                filtered.append( pair[0] )

        for key in to_delete:
            self.delete_key( key )

        # we may have to wrap the above with a try .. except and handle strptime() exceptions
        return filtered


# --------------------------------------------------------------------------------
# a custom BaseHTTPRequestHandler mixin 

## class CustomRedisMixin(object):
class CustomRedisMixin:

    # we do _not_ expect to receive these through any headers ;
    # on the contrary, this stuff is expected to stay on the server and never leave it
    #
    # also, currently we are going to generate a new key once a day 
    # ( on the days when there's _any_ activity ) ;
    # below settings shall also tell how many keys to keep until we expire some
    #
    redis_params = {
        # redis host
        'host' : 'localhost'
        # redis port ( 6379 is redis default )
    ,   'port' : 6379
        # how many days ( or, to be more accurate, _distinct keys_ ) to keep
    ,   'keep_days' : KEY_HISTORY_MAXLEN
    }

    # -------------------------------------------------------------------------
    
    @classmethod
    def set_redis_params(cls, redis_params):
        
        rp = cls.redis_params
        
        declared = set(rp.keys())
        present = set( redis_params.keys() )
        
        # check that there are no unexpected keys
        assert not ( present - declared )
        
        rp.update( redis_params )
    

    def get_redis_params(self):
        return self.redis_params


    def get_set_enc_keys( self ):
        """
            - retrieve existing storage keys from the database ;
            - create a new storage key and check if it is present ;
            - create a new encryption key (  == storage value ) if not ;
            - attempt adding a new (key, value) pair ;
            - expire old keys ;
            - retrieve storage values ( == encryption keys ) for other storage keys
            
            return value:
              - a list of current up-to-date pairs ( key, value ), 
                where 'key' is the storage key, 
                and 'value' is the stored value ( encryption key )
        """

        redis_params = self.get_redis_params()
        keep_days = redis_params[ 'keep_days' ]

        db = getattr( self, '_db', None )
        if db is None:
            self._db = db = RedisWrapper( host=redis_params['host'], port = redis_params['port'] )

        storage_keys = db.keys( sort_keys = True ) # this shall start with oldest first
        
        # make today's key and check if it's there
        new_storage_key = db.new_key()
        
        if new_storage_key not in storage_keys:

            self.log_message("storage key '%s' not in the current set, adding a new key/value pair ..", new_storage_key)

            encryption_key = Fernet.generate_key()
            # this may return False if another process have already added that key
            # // most likely with a different value
            added = db.add( new_storage_key, encryption_key )

            self.log_message( "adding key '%s' : '%s'", new_storage_key, added )

            # if added :
            # // shall not happen too often anyway
            if 1:
                self.log_message( "expiring old keys with timeout of %s days ...", keep_days )
                # expires the keys starting of now
                filtered = db.expire_keys( timeout_seconds = keep_days * DAYS )
                storage_keys = filtered

        #
        # at this point, any storage key in 'storage_keys' is considered valid
        #

        keys_as_text = '|'.join( storage_keys )
        self.log_message( "current storage keys: '%s'", keys_as_text )

        pairs = [ (st_key, db.get(st_key, None)) for st_key in storage_keys ]
        correct_keys = [ p for p in pairs if p[1] is not None ]

        return correct_keys


    def decrypt_cookie( self, encrypted_cookie, storage_pairs, sort = False ):
        """
            attempt decryption, return None if it fails ;
            'pairs' are ( storage_key, encryption_value ),
            as returned by .get_set_enc_keys()
            
            returns ( storage_key, result ) or None
        """

        result = None # default return value

        sorted_pairs = storage_pairs
        # newest first
        if sort:
            sorted_pairs = storage_pairs.sort( reverse = True )

        decoded = None
        for p in sorted_pairs:
            
            storage_key = p[0]
            self.log_message( "trying key '%s'", storage_key )
            f = Fernet(p[1])
            try:
                decoded = f.decrypt( encrypted_cookie )
                break
            except InvalidToken as e:
                self.log_message("no luck for key '%s', continue ...", storage_key)
        
        if decoded is not None:
            
            self.log_message( "encrypted cookie decrypted with key '%s', decoding json ...", storage_key )
            # expect json-packed data
            data = json_loads( decoded )
            # use the last 'storage_key' -- it shall be the right one )
            result = ( storage_key, data )

        return result


    def encrypt_cookie( self, raw_data, encryption_key ):

        data_as_text = json_dumps( raw_data )

        f = Fernet( encryption_key )
        result = f.encrypt( data_as_text )

        return result


    def format_cookie( self, name, value, secure = False, max_age = None, header='Set-Cookie:', sep='\r\n' ):
        """
            cookie formatting and encoding ;
            return the cookie as text
        """
        # will probably have to add max_age from name_attrs

        # [ https://pymotw.com/2/Cookie/ ]
        c = BaseCookie()
        c[name] = value
        if secure:
            c[name]['secure'] = True
        if max_age:
            c[name]['max-age'] = max_age

        result = c.output( header=header, sep=sep )

        # nb: could be many lines
        return result

        ##
        ##  cookie_text = "{}={}; httponly".format( self._cookie_name, enc )
        ##  ## cookie_attrs = None
        ##  if self._set_secure_cookie:
        ##      # [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Secure ]
        ##      ## cookie_text += b'; secure'
        ##      cookie_text += '; secure'
        ##      # for more attributes, join them through an ':'
        ##      ## cookie_attrs = "{}_attrs=secure; httponly; secure".format( self._cookie_name )
        ##  
        ##  self.log_message( "setting a cookie for user '%s' ... ", user )
        ##  
        ##  cookie_bytes = ensure_bytes( cookie_text )
        ##  self.send_header( 'Set-Cookie', cookie_bytes )
        ##
    


# --------------------------------------------------------------------------------

if __name__ == "__main__":

    for fname in sys.argv[1:] :

        pass



