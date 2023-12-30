#
# Copyright 2023 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import re
from .Filter import *
import sys

class base_op:
    action = ""
    operation = ""
    profile = ""
    name = ""
    pid = ""
    comm = ""

    priority = 99
    parsed_dict = {}

    def __init__(self):
        return

    def __hash__(self):
        raise NotImplementedError

    def __eq__(self, rule):
        raise NotImplementedError

    def __repr__(self):
        raise NotImplementedError

    def parse(self, parsed_dict):
        if not parsed_dict:
            raise Exception("parsed_dict is None")
        if ("action" in parsed_dict) and parsed_dict["action"]:
            self.action = parsed_dict["action"]
        if ("operation" in parsed_dict) and parsed_dict["operation"]:
             self.operation = parsed_dict["operation"]
        if ("profile" in parsed_dict) and parsed_dict["profile"]:
             self.profile = parsed_dict["profile"]
        if ("name" in parsed_dict) and parsed_dict["name"]:
             self.name = parsed_dict["name"]
        if ("pid" in parsed_dict) and parsed_dict["pid"]:
             self.pid = parsed_dict["pid"]
        if ("comm" in parsed_dict) and parsed_dict["comm"]:
             self.comm = parsed_dict["comm"]

    def isDuplicate(self):
        print("WARNING: Pure virtual call to base_op: isDuplicate")
        return False

# Capabilities
class OpCapable(base_op):
    capability = -1
    capname = ""
    priority = 5

    def __init__(self):
        base_op.__init__(self)

    def parse(self, parsed_dict):
        if not self.isType(parsed_dict):
            return False

        base_op.parse(self, parsed_dict)

        if ("capability" in parsed_dict) and parsed_dict["capability"]:
            self.capability = parsed_dict["capability"]
        if ("capname" in parsed_dict) and parsed_dict["capname"]:
            self.capname = parsed_dict["capname"]

        return True

    def isType(self, parsed_dict):
        # XXX We can also check operation
        if "capability" in parsed_dict:
            return True
        if "capname" in parsed_dict:
            return True
        if "capable" in parsed_dict["operation"]:
            return True
        return False

    def isDuplicate(self):
        return False

    def getDefaultRule(self):
        if self.capname:
            return "capability " + self.capname.strip("\"")

        if self.name:
            return "capability " + self.name.strip("\"")

    def __hash__(self):
        return hash(("capability ", self.capname.strip("\"")))

    def __eq__(self, rule):
        return isinstance(rule, OpCapable) and \
                self.capname.strip("\"") == rule.capname.strip("\"")

    def __lt__(self, rule):
        return ((self.capname.strip("\"").lower(), self.capability) <
                (rule.capname.strip("\"").lower(), rule.capability))

    def __repr__(self):
        # XXX I guess this would replace "getDefaultRule"?
        return 'capability ' + self.capname.strip("\"")

# File accesses
class OpFile(base_op):
    requested_mask = ""
    denied_mask = ""
    fsuid = -1
    ouid = -1
    handled = False

    priority = 10
    def __init__(self):
        base_op.__init__(self)

        return

    def parse(self, parsed_dict):
        if not self.isType(parsed_dict):
            return False

        base_op.parse(self, parsed_dict)

        if ("requested_mask" in parsed_dict) and parsed_dict["requested_mask"]:
            self.requested_mask = parsed_dict["requested_mask"]
        if ("denied_mask" in parsed_dict) and parsed_dict["denied_mask"]:
            self.denied_mask = parsed_dict["denied_mask"]
        if ("fsuid" in parsed_dict) and parsed_dict["fsuid"]:
            self.fsuid = parsed_dict["fsuid"]
        if ("ouid" in parsed_dict) and parsed_dict["ouid"]:
            self.ouid = parsed_dict["ouid"]

        self.parsed_dict = parsed_dict
        return True

    def checkFilters(self, rule):
        new_rule = rule

        f = Filter("LogTypesFilter")
        filters = f.loadFilterSet()

        # Ok, this gets messy. We assuem each filter has at least two regex patterns: the
        # pattern to match and replace, followed by a .*. We use the second one to append
        # any subsequent portions of the path. We can stack multiple filters this way,
        # but it's messy...XXX find a better way

        for f in filters:
            p = re.compile(f)
            m = p.match(rule)

            if m:
               new_rule = filters[f] + m.groups()[1]

        return new_rule


    def getDefaultRule(self):
        mask = ""
        if not self.requested_mask:
            #print("No requested_mask for rule, trying denied mask")
            if not self.denied_mask:
                print("No denied or requested mask, using default")
                mask = "rw"
            else:
                mask = self.denied_mask
        else:
            mask = self.requested_mask

        if not self.name:
            print("No name for rule, returning empty rule")
            return ""

        # We have to transform certain masks to 'w', like 'd' and 'c', since they don't map
        # directly to AppArmor profile permissions
        cur_mask = mask.replace("\"", "")
        cur_mask = cur_mask.strip(",") # Just in case

        cur_mask = cur_mask.replace("c", "w")
        cur_mask = cur_mask.replace("d", "w")

        if 'a' in cur_mask:
            cur_mask = cur_mask.replace("a", "w")

        self.name = self.name.strip("\"")

        # There are weird cases where the names are hex encoded, this doesn't work
        # in profiles, so we need to decode those
        if len(self.name) > 2 and self.name[0:2] == "2F":
            self.name = bytes.fromhex(self.name).decode('ascii')

        if '/' not in self.name:
            self.name = '/' + self.name

        # Now handle each possible permission
        new_mask = ""
        mask_chars = ['r', 'w', 'l', 'k', 'x', 'm', 'i']
        for c in mask_chars:
            if c in cur_mask:
                cur_mask = cur_mask.replace(c, '')
                if c == 'i':
                    # Do nothing since 'x' will handle this
                    c = ''
                if c == 'x':
                    c = 'ix'
                new_mask += c
        new_mask += cur_mask # This handles unknowns


        if ".so" in self.name:
            self.name = self.fixLibraryVersions(self.name)

        rule = (self.name).strip("\"") + " " + new_mask
        rule = self.checkFilters(rule)

        return rule

    # Ideally we'd use filters here, but that would require some group stuff that
    # currently isn't supported (TODO)
    def fixLibraryVersions(self, filename):
        # Running this function on the same object multiple times creates
        # a lot of problems, so skip it once it's done once
        if self.handled == True:
            return filename

        # A bit redundant but we know this is a common case, so skip it
        if "ld.so." in filename:
            return filename

        if "mod_" in filename:
            return filename

        # There are cases that are not libraries: ld.so.*, mod_* (httpd modules), and ld-*.so
        # We also have the possibility of weirdness with /lib /usr/lib, etc, so break up
        # the path, then operate only on the filename, not assuming a 'lib' prefix
        if filename.rfind('/') != -1:
            lib_name = filename[filename.rfind('/') + 1:]
            lib_path = filename[:filename.rfind('/') + 1]

        else:
            print("ERROR: Could not find / in lib path name")
            print("-> Original filename: ")
            print(filename)
            sys.exit(0)

        new_rule = ""
        new_rule += lib_path

        # If we match a version (-1.1.1.1) then replace with a wildcard
        ver_regex = "([A-Za-z\+\_]+)+(-[0-9]\.)"
        m = re.match(ver_regex, lib_name)

        if m:
            if len(m.groups()) >= 2:
                base_libname = m.groups()[0]
                new_rule += base_libname + "-*"
            else:
                print("ERROR: fixLibraryVersions() invalid regex version string match")
                print("-> Original filename: ")
                print(filename)
                sys.exit(0)
        else:
            # No version string, just use the library name
            new_rule += lib_name[:lib_name.rfind('.so')]
        new_rule += ".so"

        # If we match a suffix (.0.0.0) then replace with a wildcard
        suffix_regex = ".*\.so\.[0-9]"
        m = re.match(suffix_regex, lib_name)
        if m:
            new_rule += "*"

        self.handled = True

        # This can happen if there is a bug here or a format we do not expect, it's not
        # very likely, but is possible and it's safer to exit
        if new_rule == "/lib*.so*":
            print("ERROR: fixLibraryVersions() created an invalid entry due to a bug")
            print("-> Original filename: ")
            print(filename)
            print("Please submit the filename above as a bug report with this error.")
            sys.exit(0)

        return new_rule

    def isType(self, parsed_dict):
        # XXX We can also check operation
        #
        # XXX XXX This creates a problem with some rule types. The issue being that requested_mask is
        # more generic than just being a part of file operations. It can be used for network operations,
        # for example. So while not ideal, for now, we explicitly look for things that are associated with
        # known types that aren't files but use this mask, then exclude those.
        # We should be looking to see if name and operation line up here, not doing this.
        # XXX XXX Fix this

        if "sock_type" in parsed_dict:
            return False
        if "family" in parsed_dict:
            return False
        if "signal" in parsed_dict:
            return False
        if "ptrace" in parsed_dict["operation"]:
            return False
        if "capable" in parsed_dict["operation"]:
            return False
        if "requested_mask" in parsed_dict:
            return True
        if "denied_mask" in parsed_dict:
            return True
        return False

    def isDuplicate(self):
        # Handle cases where the file name is the same, but permissions differ
        # XXX

        # Handle cases where there is a numeric suffix (e.g. .1, .2)
        # XXX
        #XXX This should tell the parent to remove other duplicates
        return False

    def __hash__(self):
        # XXX Not sure if this works (same with capable), need to test.
        return hash(((self.name).strip("\""), self.requested_mask.strip("\"")))

    def __eq__(self, rule):
        return ((self.name.lower(), self.requested_mask.lower()) ==
                (rule.name.lower(), rule.requested_mask.lower()))

    def __lt__(self, rule):
        return ((self.name.lower(), self.requested_mask.lower()) <
                 (rule.name.lower(), self.requested_mask.lower()))

    def __repr__(self):
        # XXX I guess this would replace "getDefaultRule"?
        return (self.name).strip("\"") + " " + self.requested_mask.strip("\"")

# v2 Networking
class OpNetwork(base_op):
    priority = 6

    family = ""
    sock_type = ""

    def __init__(self):
        base_op.__init__(self)

    def parse(self, parsed_dict):
        if not self.isType(parsed_dict):
            return False

        base_op.parse(self, parsed_dict)

        if ("requested_mask" in parsed_dict) and parsed_dict["requested_mask"]:
            self.requested_mask = parsed_dict["requested_mask"]
        if ("denied_mask" in parsed_dict) and parsed_dict["denied_mask"]:
            self.denied_mask = parsed_dict["denied_mask"]
        if ("family" in parsed_dict) and parsed_dict["family"]:
            self.family = parsed_dict["family"]
        if ("sock_type" in parsed_dict) and parsed_dict["sock_type"]:
            self.sock_type = parsed_dict["sock_type"]

        return True

    def isType(self, parsed_dict):
        # Be careful using requested/denied_mask here, since file ops use that
        # too
        if "sock_type" in parsed_dict:
            return True
        if "family" in parsed_dict:
            return True
        return False

    def isDuplicate(self):
        return False

    def getDefaultRule(self):
        family = self.family.strip("\"") # no backspace allowed in f string >.>
        return f'network {family}'

    def getComment(self):
        # For now, rules are just allowing the entire family and the rest of
        # the metadata goes into a comment. We prefix the comment with "NETCOM"
        # to allow us to easily filter this out later.
        opc = OpComment()
        opc.comment = f"# NETCOM - {self.family} {self.sock_type} {self.operation}"
        return opc

    def __hash__(self):
        return hash(self.family.strip("\""))

    def __eq__(self, rule):
        return self.family.strip("\"") == rule.family.strip("\"")

    def __lt__(self, rule):
        return ((self.capname.strip("\"").lower(), self.capability) <
                (rule.capname.strip("\"").lower(), rule.capability))

    def __repr__(self):
        return self.family.strip("\"")

# Comments
class OpComment(base_op):
    priority = 7

    comment = ""

    def __init__(self):
        base_op.__init__(self)

    def parse(self, parsed_dict):
        return False

    def isType(self, parsed_dict):
        return False

    def isDuplicate(self):
        return False

    def getDefaultRule(self):
        return self.comment.strip("\"")

    def __hash__(self):
        return hash(self.comment)

    def __eq__(self, rule):
        return self.comment == rule.comment

    def __repr__(self):
        return self.comment

# ptrace
class OpPtrace(base_op):
    priority = 10

    def __init__(self):
        base_op.__init__(self)

    def parse(self, parsed_dict):
        if not self.isType(parsed_dict):
            return False

        base_op.parse(self, parsed_dict)

        return True

    def isType(self, parsed_dict):
        # XXX We can also check operation
        if "operation" in parsed_dict and "ptrace" in parsed_dict["operation"]:
            return True
        return False

    def isDuplicate(self):
        # XXX -- this can be replaced with the __eq__ function right?
        return False

    def getDefaultRule(self): # XXX with __repr__ maybe we can remove this.
        return "ptrace"

    def __hash__(self):
        return hash(("ptrace"))

    def __eq__(self, rule):
        return isinstance(rule, OpPtrace) and self.getDefaultRule() == rule.getDefaultRule()

    def __lt__(self, rule):
        return False

    def __repr__(self):
        # XXX I guess this would replace "getDefaultRule"?
        return "ptrace"

# Signal
#
# Signals get kindof complicated, because both sender and receiver
# must have some coordination of the signal required. For now,
# we just allow all signal access when signal logs are encountered.
# We can revise this at a later date (TODO)
class OpSignal(base_op):
    signal = ""
    requested_mask = ""
    priority = 9

    def __init__(self):
        base_op.__init__(self)

    def parse(self, parsed_dict):
        if not self.isType(parsed_dict):
            return False

        base_op.parse(self, parsed_dict)

        if ("signal" in parsed_dict) and parsed_dict["signal"]:
            self.signal = parsed_dict["signal"]

        if ("requested_mask" in parsed_dict) and parsed_dict["requested_mask"]:
            self.requested_mask = parsed_dict["requested_mask"]

        return True

    def isType(self, parsed_dict):
        if "signal" in parsed_dict:
            return True
        return False

    def isDuplicate(self):
        return False

    def getDefaultRule(self):
        return "signal"

    def __hash__(self):
        return hash(("signal"))

    def __eq__(self, rule):
        return isinstance(rule, OpSignal) and self.getDefaultRule() == rule.getDefaultRule()

    def __lt__(self, rule):
        return False

    def __repr__(self):
        return "signal"
