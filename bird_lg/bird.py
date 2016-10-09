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

import socket
import sys

__all__ = ['BirdSocketSingleton', 'BirdSocket']

BUFSIZE = 4096

SUCCESS_CODES = {
    "0000": "OK",
    "0001": "Welcome",
    "0002": "Reading configuration",
    "0003": "Reconfigured",
    "0004": "Reconfiguration in progress",
    "0005": "Reconfiguration already in progress, queueing",
    "0006": "Reconfiguration ignored, shutting down",
    "0007": "Shutdown ordered",
    "0008": "Already disabled",
    "0009": "Disabled",
    "0010": "Already enabled",
    "0011": "Enabled",
    "0012": "Restarted",
    "0013": "Status report",
    "0014": "Route count",
    "0015": "Reloading",
    "0016": "Access restricted",
}

TABLES_ENTRY_CODES = {
    "1000": "BIRD version",
    "1001": "Interface list",
    "1002": "Protocol list",
    "1003": "Interface address",
    "1004": "Interface flags",
    "1005": "Interface summary",
    "1006": "Protocol details",
    "1007": "Route list",
    "1008": "Route details",
    "1009": "Static route list",
    "1010": "Symbol list",
    "1011": "Uptime",
    "1012": "Route extended attribute list",
    "1013": "Show ospf neighbors",
    "1014": "Show ospf",
    "1015": "Show ospf interface",
    "1016": "Show ospf state/topology",
    "1017": "Show ospf lsadb",
    "1018": "Show memory",
}

ERROR_CODES = {
    "8000": "Reply too long",
    "8001": "Route not found",
    "8002": "Configuration file error",
    "8003": "No protocols match",
    "8004": "Stopped due to reconfiguration",
    "8005": "Protocol is down => cannot dump",
    "8006": "Reload failed",
    "8007": "Access denied",

    "9000": "Command too long",
    "9001": "Parse error",
    "9002": "Invalid symbol type",
}

END_CODES = ERROR_CODES.keys() + SUCCESS_CODES.keys()

global bird_sockets
bird_sockets = {}


def BirdSocketSingleton(host, port):
    global bird_sockets
    s = bird_sockets.get((host, port), None)
    if not s:
        s = BirdSocket(host, port)
        bird_sockets[(host, port)] = s
    return s


class BirdSocket(object):
    def __init__(self, host="", port="", file=""):
        self.__file = file
        self.__host = host
        self.__port = port
        self.__sock = None

    def __connect(self):
        if self.__sock:
            return

        if not file:
            self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__sock.settimeout(3.0)
            self.__sock.connect((self.__host, self.__port))
        else:
            self.__sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.__sock.settimeout(3.0)
            self.__sock.connect(self.__file)

        # read welcome message
        self.__sock.recv(1024)
        self.cmd("restrict")

    def close(self):
        if self.__sock:
            try:
                self.__sock.close()
            except Exception:
                pass
            self.__sock = None

    def cmd(self, cmd):
        try:
            self.__connect()
            self.__sock.send(cmd + "\n")
            data = self.__read()
            return data
        except socket.error:
            why = sys.exc_info()[1]
            self.close()
            return False, "Bird connection problem: %s" % why

    def __read(self):
        code = "7000"  # Not used  in bird
        parsed_string = ""
        lastline = ""

        while code not in END_CODES:
            data = self.__sock.recv(BUFSIZE)

            lines = (lastline + data).split("\n")
            if len(data) == BUFSIZE:
                lastline = lines[-1]
                lines = lines[:-1]

            for line in lines:
                code = line[0:4]

                if not line.strip():
                    continue
                elif code == "0000":
                    return True, parsed_string
                elif code in SUCCESS_CODES.keys():
                    return True, SUCCESS_CODES.get(code)
                elif code in ERROR_CODES.keys():
                    return False, ERROR_CODES.get(code)
                elif code[0] in ["1", "2"]:
                    parsed_string += line[5:] + "\n"
                elif code[0] == " ":
                    parsed_string += line[1:] + "\n"
                elif code[0] == "+":
                    parsed_string += line[1:]
                else:
                    parsed_string += "<<<unparsable_string(%s)>>>\n" % line

        return True, parsed_string
