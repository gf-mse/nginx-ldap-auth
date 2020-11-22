#!/usr/bin/python

# Copyright (C) 2014-2015 Nginx, Inc.

"""
    a simple / demo "backend" which just prints headers
"""


import sys, os, signal, base64, cgi
if sys.version_info.major == 2:
    from urlparse import urlparse
    from Cookie import BaseCookie
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
elif sys.version_info.major == 3:
    from urllib.parse import urlparse
    from http.cookies import BaseCookie
    from http.server import HTTPServer, BaseHTTPRequestHandler

Listen = ('localhost', 9001)

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

    # [ https://pymotw.com/2/BaseHTTPServer/#http-get ]
    def do_GET(self):

        parsed_path = urlparse.urlparse(self.path)

        message_parts = [
                'CLIENT SENT:',
                'client_address=%s (%s)' % (self.client_address,
                                            self.address_string()),
                'command=%s' % self.command,
                'path=%s' % self.path,
                'real path=%s' % parsed_path.path,
                'query=%s' % parsed_path.query,
                'request_version=%s' % self.request_version,
                '',
                'HEADERS:',
                ]
        for name, value in sorted(self.headers.items()):
            if name.lower() in ('authorization', 'cookie'):
                value = '***'
            message_parts.append('%s=%s' % (name, value.rstrip()))
        message_parts.append('')
        message = '\r\n'.join(message_parts)

        self.send_response(200)
        self.end_headers()

        self.wfile.write( ensure_bytes(message) )


    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        sys.stdout.write("%s - - [%s] %s\n" % (addr,
                         self.log_date_time_string(), format % args))

    def log_error(self, format, *args):
        self.log_message(format, *args)


def exit_handler(signal, frame):
    sys.exit(0)

if __name__ == '__main__':
    server = AuthHTTPServer(Listen, AppHandler)

    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    server.serve_forever()
