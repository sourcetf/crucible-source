#!/bin/sh
# Minimal CGI sample
printf 'Content-Type: text/plain; charset=utf-8\r\n\r\n'
printf 'hello from cgi path=%s method=%s\n' "${PATH_INFO:-/}" "${REQUEST_METHOD:-GET}"
