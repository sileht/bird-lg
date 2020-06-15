#!/usr/bin/python
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


import sys
import logging
from logging.handlers import TimedRotatingFileHandler
from logging import FileHandler
import subprocess
from urllib import unquote
import argparse

from bird import BirdSocket

from flask import Flask, request, abort

parser = argparse.ArgumentParser()
parser.add_argument('-c', dest='config_file', help='path to config file', default='lgproxy.cfg')
args = parser.parse_args()

app = Flask(__name__)
app.debug = app.config["DEBUG"]
app.config.from_pyfile(args.config_file)

file_handler = TimedRotatingFileHandler(filename=app.config["LOG_FILE"], when="midnight") 
app.logger.setLevel(getattr(logging, app.config["LOG_LEVEL"].upper()))
app.logger.addHandler(file_handler)

@app.before_request
def access_log_before(*args, **kwargs):
    app.logger.info("[%s] request %s, %s", request.remote_addr, request.url, "|".join(["%s:%s"%(k,v) for k,v in request.headers.items()]))

@app.after_request
def access_log_after(response, *args, **kwargs):
    app.logger.info("[%s] reponse %s, %s", request.remote_addr,  request.url, response.status_code)
    return response

def check_security():
    if app.config["ACCESS_LIST"] and request.remote_addr not in app.config["ACCESS_LIST"]:
        app.logger.info("Your remote address is not valid")
        abort(401)

    if app.config.get('SHARED_SECRET') and request.args.get("secret") != app.config["SHARED_SECRET"]:
        app.logger.info("Your shared secret is not valid")
        abort(401)

@app.route("/traceroute")
@app.route("/traceroute6")
def traceroute():
    check_security()
    
    if sys.platform.startswith('freebsd') or sys.platform.startswith('netbsd') or sys.platform.startswith('openbsd'):
        traceroute4 = [ 'traceroute' ]
        traceroute6 = [ 'traceroute6' ]
    else: # For Linux
        traceroute4 = [ 'traceroute', '-4' ]
        traceroute6 = [ 'traceroute', '-6' ]

    src = []
    if request.path == '/traceroute6': 
	traceroute = traceroute6
	if app.config.get("IPV6_SOURCE",""):
	     src = [ "-s",  app.config.get("IPV6_SOURCE") ]

    else: 
	traceroute = traceroute4
	if app.config.get("IPV4_SOURCE",""):
	     src = [ "-s",  app.config.get("IPV4_SOURCE") ]

    query = request.args.get("q","")
    query = unquote(query)

    if sys.platform.startswith('freebsd') or sys.platform.startswith('netbsd'):
        options = [ '-a', '-q1', '-w1', '-m15' ]
    elif sys.platform.startswith('openbsd'):
        options = [ '-A', '-q1', '-w1', '-m15' ]
    else: # For Linux
        options = [ '-A', '-q1', '-N32', '-w1', '-m15' ]
    command = traceroute + src + options + [ query ]
    result = subprocess.Popen( command , stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore').replace("\n","<br>")
    
    return result



@app.route("/bird")
@app.route("/bird6")
def bird():
    check_security()

    if request.path == "/bird": b = BirdSocket(file=app.config.get("BIRD_SOCKET"))
    elif request.path == "/bird6": b = BirdSocket(file=app.config.get("BIRD6_SOCKET"))
    else: return "No bird socket selected"

    query = request.args.get("q","")
    query = unquote(query)

    status, result = b.cmd(query)
    b.close()
    # FIXME: use status
    return result
	

if __name__ == "__main__":
    app.logger.info("lgproxy start")
    app.run(app.config.get("BIND_IP", "0.0.0.0"), app.config.get("BIND_PORT", 5000))
