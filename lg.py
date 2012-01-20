#!/usr/bin/python

import sys
import os
import subprocess
import re

from toolbox import mask_is_valid, ipv6_is_valid, ipv4_is_valid, resolve

from bird import BirdSocketSingleton
from flask import Flask, render_template, jsonify, redirect, session, request

app = Flask(__name__)
app.config.from_pyfile('lg.cfg')


def add_links(text):
	if type(text) in [ str, unicode ]:
		text = text.split("\n")

	ret_text = []
	for line in text:
		if line.strip().startswith("BGP.as_path:") or \
			line.strip().startswith("Neighbor AS:") :
			ret_text.append(re.sub(r'(\d+)',r'<a href="/whois/\1" class="whois">\1</a>',line))
		else:
			line = re.sub(r'AS(\d+)', r'<a href="/whois/\1" class="whois">AS\1</a>',line)
			line = re.sub(r'(\d+\.\d+\.\d+\.\d+)', r'<a href="/whois/\1" class="whois">\1</a>',line)
			ret_text.append(line)
	return "\n".join(ret_text)

def set_session(req_type, hosts, proto, request_args):
	session.update( {
		"req_type": req_type,
		"hosts": hosts,
		"proto": proto,
		"request_args": request_args,
	})

def bird_command(host, proto, command):
	conf = app.config["HOST_MAPPING"].get(host, None)
	port = conf.get(proto)
	if not conf or not port:
		return False, "Host/Proto not allowed"
	else:
		b = BirdSocketSingleton(host, port)
		return b.cmd(command)
		
@app.context_processor
def inject_all_host():
	return dict(all_hosts="+".join(app.config["HOST_MAPPING"].keys()))

@app.route("/")
def hello():
	return redirect("/summary/%s/ipv4" % "+".join(app.config["HOST_MAPPING"].keys()) )

def error_page(text):
	return render_template('error.html', data = { "error": text } ), 500


@app.route("/whois/<query>")
def whois(query):
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
	for host in hosts.split("+"):
		ret, res = bird_command(host, proto, command)
		res = res.split("\n")
		if ret:
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
			summary[host] = { "error" : res }

	return render_template('summary.html', summary=summary, command=command)

@app.route("/detail/<hosts>/<proto>")
def detail(hosts, proto):
	name = request.args.get('q', '')
	set_session("detail", hosts, proto, name)
	command = "show protocols all %s" % name

	detail = {}
	for host in hosts.split("+"):
		ret, res = bird_command(host, proto, command)
		res = res.split("\n")
		if ret:
			detail[host] = { "status": res[1], "description": add_links(res[2:]) }
		else:
			detail[host] = { "status": "bird error: %s" % "\n".join(res), "description": "" }
	
	return render_template('detail.html', detail=detail, command=command)

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

def show_route(req_type, hosts, proto):
	expression = request.args.get('q', '')
	set_session(req_type, hosts, proto, expression)

	all = (req_type.endswith("detail") and " all" or "" )

	if req_type.startswith("where"):
		command = "show route where net ~ [ " + expression + " ]" + all
	else:
		mask = ""
		if len(expression.split("/")) > 1:
			expression, mask = (expression.split("/"))

		if not mask and proto == "ipv4" : mask = "32"
		if not mask and proto == "ipv6" : mask = "128"
		if not mask_is_valid(mask):
			return error_page("mask %s invalid" % mask)
		if proto == "ipv6" and not ipv6_is_valid(expression):
			try: expression = resolve(expression, "AAAA")
			except:	return error_page("%s unresolvable/invalid" % expression)
		if proto == "ipv4" and not ipv4_is_valid(expression):
			try: expression = resolve(expression, "A")
			except:	return error_page("%s unresolvable/invalid" % expression)

		if mask: expression += "/" + mask
		command = "show route for " + expression + all

	detail = {}
	for host in hosts.split("+"):
		ret, res = bird_command(host, proto, command)

		res = res.split("\n")
		if ret:
			detail[host] = add_links(res)
		else:
			detail[host] = "bird error: %s" % "\n".join(res)
	
	return render_template('route.html', detail=detail, command=command, expression=expression )

app.secret_key = app.config["SESSION_KEY"]
app.debug = True
if __name__ == "__main__":
	app.run("0.0.0.0")
