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


import logging
from logging import handlers
import subprocess
import sys
import urllib

import flask

import bird

app = flask.Flask(__name__)
app.debug = app.config["DEBUG"]
app.config.from_pyfile('lgproxy.cfg')

file_handler = handlers.TimedRotatingFileHandler(
    filename=app.config["LOG_FILE"], when="midnight")
app.logger.setLevel(getattr(logging, app.config["LOG_LEVEL"].upper()))
app.logger.addHandler(file_handler)


@app.before_request
def access_log_before(*args, **kwargs):
    app.logger.info("[%s] flash.request %s, %s",
                    flask.request.remote_addr,
                    flask.request.url, "|".join(
                        ["%s:%s" % (k, v) for k, v in
                         flask.request.headers.items()])
                    )


@app.after_request
def access_log_after(response, *args, **kwargs):
    app.logger.info("[%s] reponse %s, %s", flask.request.remote_addr,
                    flask.request.url, response.status_code)
    return response


def check_accesslist():
    if (app.config["ACCESS_LIST"] and
            flask.request.remote_addr not in app.config["ACCESS_LIST"]):
        flask.abort(401)


@app.route("/traceroute")
@app.route("/traceroute6")
def traceroute():
    check_accesslist()

    if (sys.platform.startswith('freebsd') or sys.platform.startswith('netbsd')
            or sys.platform.startswith('openbsd')):
        traceroute4 = ['traceroute']
        traceroute6 = ['traceroute6']
    else:  # For Linux
        traceroute4 = ['traceroute', '-4']
        traceroute6 = ['traceroute', '-6']

    src = []
    if flask.request.path == '/traceroute6':
        traceroute = traceroute6
        if app.config.get("IPV6_SOURCE", ""):
            src = ["-s",  app.config.get("IPV6_SOURCE")]
    else:
        traceroute = traceroute4
        if app.config.get("IPV4_SOURCE", ""):
            src = ["-s",  app.config.get("IPV4_SOURCE")]

    query = flask.request.args.get("q", "")
    query = urllib.unquote(query)

    if sys.platform.startswith('freebsd') or sys.platform.startswith('netbsd'):
        options = ['-a', '-q1', '-w1', '-m15']
    elif sys.platform.startswith('openbsd'):
        options = ['-A', '-q1', '-w1', '-m15']
    else:  # For Linux
        options = ['-A', '-q1', '-N32', '-w1', '-m15']
    command = traceroute + src + options + [query]
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    return p.communicate()[0].decode('utf-8', 'ignore').replace("\n", "<br>")


@app.route("/bird")
@app.route("/bird6")
def bird_query():
    check_accesslist()

    if flask.request.path == "/bird":
        b = bird.BirdSocket(file=app.config.get("BIRD_SOCKET"))
    elif flask.request.path == "/bird6":
        b = bird.BirdSocket(file=app.config.get("BIRD6_SOCKET"))
    else:
        return "No bird socket selected"

    query = flask.request.args.get("q", "")
    query = urllib.unquote(query)

    status, result = b.cmd(query)
    b.close()
    # FIXME: use status
    return result


if __name__ == "__main__":
    app.logger.info("lgproxy start")
    app.run("0.0.0.0")
