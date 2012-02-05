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
import os
import subprocess
import re
from urllib2 import urlopen
from urllib import quote, unquote

from toolbox import mask_is_valid, ipv6_is_valid, ipv4_is_valid, resolve

from bird import BirdSocketSingleton
from flask import Flask, render_template, jsonify, redirect, session, request, abort

app = Flask(__name__)
app.config.from_pyfile('lg.cfg')

def add_links(text):
	if type(text) in [ str, unicode ]:
		text = text.split("\n")

	ret_text = []
	for line in text:
		# Some heuristic to create link
		if line.strip().startswith("BGP.as_path:") or \
			line.strip().startswith("Neighbor AS:") :
			ret_text.append(re.sub(r'(\d+)',r'<a href="/whois/\1" class="whois">\1</a>',line))
		else:
			line = re.sub(r'([a-zA-Z0-9\-]*\.([a-zA-Z]{2,3}){1,2})(\s|$)', r'<a href="/whois/\1" class="whois">\1</a>',line)
			line = re.sub(r'AS(\d+)', r'<a href="/whois/\1" class="whois">AS\1</a>',line)
			line = re.sub(r'(\d+\.\d+\.\d+\.\d+)', r'<a href="/whois/\1" class="whois">\1</a>',line)
			hosts = "/".join(request.path.split("/")[2:])
			line = re.sub(r'\[(\w+)\s+((|\d\d\d\d-\d\d-\d\d\s)(|\d\d:)\d\d:\d\d|\w\w\w\d\d)', r'[<a href="/detail/%s?q=\1">\1</a> \2' % hosts, line)
			line = re.sub(r'(^|\s+)(([a-f\d]{0,4}:){3,10}[a-f\d]{0,4})', r'\1<a href="/whois/\2" class="whois">\2</a>',line , re.I)
			ret_text.append(line)
	return "\n".join(ret_text)

def set_session(request_type, hosts, proto, request_args):
	session.permanent = True
	session.update( {
		"request_type": request_type,
		"hosts": hosts,
		"proto": proto,
		"request_args": request_args,
	})
	history = session.get("history", [])

	# erase old format history
	if type(history) != type(list()): history = []

	t = (hosts, proto, request_type, request_args)
	if t in history:
		del history[history.index(t)]
	history.insert(0, t)
	session["history"] = history[:20]

def bird_command(host, proto, query):
	return bird_proxy(host, proto, "bird", query)

def bird_proxy(host, proto, service, query):
	path = ""
	if proto == "ipv6": path = service + "6"
	elif proto == "ipv4": path = service
	port = app.config["PROXY"].get(host,"")
	if not port or not path:
		return False, "Host/Proto not allowed"
	else:
		url = "http://%s.%s:%d/%s?q=%s" % (host, app.config["DOMAIN"], port, path, quote(query))
		try:
			f = urlopen(url)
			resultat = f.read()
			status = True # retreive remote status
		except IOError:
			resultat = "Failed retreive url: %s" % url
			status = False
		return status, resultat
		
@app.context_processor
def inject_commands():
	commands = [
			("traceroute","traceroute ..."),
			("summary","show protocols"),
			("detail","show protocols ... all"),
			("prefix","show route for ..."),
			("prefix_detail","show route for ... all"),
			("where","show route where net ~ [ ... ]"),
			("where_detail","show route where net ~ [ ... ] all"),
			("adv","show route ..."),
		]
	commands_dict = {}
	for id, text in commands:
		commands_dict[id] = text
	return dict(commands=commands, commands_dict=commands_dict)

@app.context_processor
def inject_all_host():
	return dict(all_hosts="+".join(app.config["PROXY"].keys()))

@app.route("/")
def hello():
	return redirect("/summary/%s/ipv4" % "+".join(app.config["PROXY"].keys()) )

def error_page(text):
	return render_template('error.html', error = text ), 500

@app.errorhandler(400)
def page_not_found(e):
	    return render_template('error.html', warning="The server could not understand the request"), 400

@app.errorhandler(404)
def page_not_found(e):
	    return render_template('error.html', warning="The requested URL was not found on the server."), 404

@app.route("/whois/<query>")
def whois(query):
	if not query.strip(): abort(400)
	try:
		asnum = int(query)
		query = "as%d"%asnum
	except:
		m = re.match(r"[\w\d-]*\.(?P<domain>[\d\w-]+\.[\d\w-]+)$", query)
		if m: query = query.groupdict()["domain"]
	output = subprocess.Popen( [ 'whois', query], stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore').replace("\n","<br>")
	return jsonify(output=output, title=query)

SUMMARY_UNWANTED_PROTOS = ["Kernel", "Static", "Device"]
SUMMARY_RE_MATCH = r"(?P<name>[\w_]+)\s+(?P<proto>\w+)\s+(?P<table>\w+)\s+(?P<state>\w+)\s+(?P<since>((|\d\d\d\d-\d\d-\d\d\s)(|\d\d:)\d\d:\d\d|\w\w\w\d\d))($|\s+(?P<info>.*))"

@app.route("/summary/<hosts>")
@app.route("/summary/<hosts>/<proto>")
def summary(hosts, proto="ipv4"):
	set_session("summary", hosts, proto, "")
	command = "show protocols"
	
	summary = {}
	error = []
	for host in hosts.split("+"):
		ret, res = bird_command(host, proto, command)
		res = res.split("\n")
		if len(res) > 1: #if ret:
			data = []
			for line in res[1:]:
				line = line.strip()
				if line and ( line.split() + [""] )[1] not in SUMMARY_UNWANTED_PROTOS:
					m = re.match(SUMMARY_RE_MATCH ,line)
					if m:
						data.append(m.groupdict())
					else:
						app.logger.warning("couldn't parse: %s" , line)

			summary[host] = data 
		else:
			error.append("%s: bird command failed with error, %s" % (host,"\n".join(res)))

	return render_template('summary.html', summary=summary, command=command, error="<br>".join(error))

@app.route("/detail/<hosts>/<proto>")
def detail(hosts, proto):
	name = request.args.get('q', '')
	if not name.strip(): abort(400)

	set_session("detail", hosts, proto, name)
	command = "show protocols all %s" % name

	detail = {}
	error = []
	for host in hosts.split("+"):
		ret, res = bird_command(host, proto, command)
		res = res.split("\n")
		if len(res) > 1 : #if ret:
			detail[host] = { "status": res[1], "description": add_links(res[2:]) }
		else:
			error.append("%s: bird command failed with error, %s" % (host,"\n".join(res)))
	
	return render_template('detail.html', detail=detail, command=command, error="<br>".join(error))

@app.route("/traceroute/<hosts>/<proto>")
def traceroute(hosts, proto):
	q = request.args.get('q', '')
	if not q.strip(): abort(400)
	set_session("traceroute", hosts, proto, q)

	if proto == "ipv6" and not ipv6_is_valid(q):
		try: q = resolve(q, "AAAA")
		except:	return error_page("%s is unresolvable or invalid for %s" % (q, proto))
	if proto == "ipv4" and not ipv4_is_valid(q):
		try: q = resolve(q, "A")
		except:	return error_page("%s is unresolvable or invalid for %s" % (q, proto))

	infos = {}
	for host in hosts.split("+"):
		status, resultat = bird_proxy(host, proto, "traceroute", q)
		infos[host] = add_links(resultat)
	return render_template('traceroute.html', infos=infos)

@app.route("/adv/<hosts>/<proto>")
def show_route_filter(hosts, proto):
	return show_route("adv", hosts, proto)

@app.route("/where/<hosts>/<proto>")
def show_route_where(hosts, proto):
	return show_route("where", hosts, proto)

@app.route("/where_detail/<hosts>/<proto>")
def show_route_where_detail(hosts, proto):
	return show_route("where_detail", hosts, proto)

@app.route("/prefix/<hosts>/<proto>")
def show_route_for(hosts, proto):
	return show_route("prefix", hosts, proto)

@app.route("/prefix_detail/<hosts>/<proto>")
def show_route_for_detail(hosts, proto):
	return show_route("prefix_detail", hosts, proto)

def show_route(request_type, hosts, proto):
	expression = unquote(request.args.get('q', ''))
	if not expression.strip(): abort(400)
	set_session(request_type, hosts, proto, expression)

	all = (request_type.endswith("detail") and " all" or "" )

	if request_type.startswith("adv"):
		command = "show route " + expression
	elif request_type.startswith("where"):
		command = "show route where net ~ [ " + expression + " ]" + all
	else:
		mask = ""
		if len(expression.split("/")) > 1:
			expression, mask = (expression.split("/"))

		if not mask and proto == "ipv4" : mask = "32"
		if not mask and proto == "ipv6" : mask = "128"
		if not mask_is_valid(mask):
			return error_page("mask %s is invalid" % mask)
		if proto == "ipv6" and not ipv6_is_valid(expression):
			try: expression = resolve(expression, "AAAA")
			except:	return error_page("%s is unresolvable or invalid for %s" % (expression, proto))
		if proto == "ipv4" and not ipv4_is_valid(expression):
			try: expression = resolve(expression, "A")
			except:	return error_page("%s is unresolvable or invalid for %s" % (expression, proto))

		if mask: expression += "/" + mask
		command = "show route for " + expression + all

	detail = {}
	error = []
	for host in hosts.split("+"):
		ret, res = bird_command(host, proto, command)

		res = res.split("\n")
		if len(res) > 1 : #if ret:
			detail[host] = add_links(res)
		else:
			error.append("%s: bird command failed with error, %s" % (host,"\n".join(res)))
	
	return render_template('route.html', detail=detail, command=command, expression=expression, error="<br>".join(error) )

app.secret_key = app.config["SESSION_KEY"]
app.debug = True
if __name__ == "__main__":
	app.run("0.0.0.0")
