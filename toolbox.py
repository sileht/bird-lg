# -*- coding: utf-8 -*-
# vim: ts=4
###
#
# Copyright (c) 2006 Mehdi Abaakouk
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
###

from dns import resolver
import socket
import pickle
import xml.parsers.expat

def resolve(n, q):
	return str(resolver.query(n,q)[0])

def get_asn_from_as(n):
    data = resolve("AS%s.asn.cymru.com" % n ,"TXT").replace("'","").replace('"','')
    return [ field.strip() for field in data.split("|") ]

def mask_is_valid(n):
	if not n: 
		return True
	try:
		mask = int(n)
		return ( mask >= 1 and mask <= 128)
	except:
		return False

def ipv4_is_valid(n):
    try:
        socket.inet_pton(socket.AF_INET, n)
        return True
    except socket.error:
        return False

def ipv6_is_valid(n):
    try:
        socket.inet_pton(socket.AF_INET6, n)
        return True
    except socket.error:
        return False

def save_cache_pickle(filename, data):
	output = open(filename, 'wb')
	pickle.dump(data, output)
	output.close()

def load_cache_pickle(filename, default = None):
	try:
		pkl_file = open(filename, 'rb')
	except IOError:
		return default
	try:
		data = pickle.load(pkl_file)
	except:
		data = default
	pkl_file.close()
	return data

def unescape(s):
    want_unicode = False
    if isinstance(s, unicode):
        s = s.encode("utf-8")
        want_unicode = True

    # the rest of this assumes that `s` is UTF-8
    list = []

    # create and initialize a parser object
    p = xml.parsers.expat.ParserCreate("utf-8")
    p.buffer_text = True
    p.returns_unicode = want_unicode
    p.CharacterDataHandler = list.append

    # parse the data wrapped in a dummy element
    # (needed so the "document" is well-formed)
    p.Parse("<e>", 0)
    p.Parse(s, 0)
    p.Parse("</e>", 1)

    # join the extracted strings and return
    es = ""
    if want_unicode:
        es = u""
    return es.join(list)
