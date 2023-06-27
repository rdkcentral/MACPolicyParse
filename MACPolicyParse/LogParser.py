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

from .ProfileTypes import *
from .Filter import *
import re
from .LogTypes import *

class ParseAppArmorMessage:
    time_regex = r'\[\s+(\d+\.\d+)\]'
    epoch_regex = r'audit\((\d+\.\d+:\d+)\)'
    aa_msg = False
    obj = None

    def __init__(self, msg=None):
        self.original = msg
        self.parsed_msg = {}
        if not self.isAppArmorMessage(msg):
            self.aa_msg = False
            return # parse everything
        self.aa_msg = True
        return

    def parse(self, msg):
        if not msg:
            return
        time = re.search(self.time_regex, msg)
        if time:
            self.parsed_msg["time"] = time.group(1)
        epoch = re.search(self.epoch_regex, msg)
        if epoch:
            self.parsed_msg["audit_epoch"] = epoch.group(1)

        #
        # This is convoluted because we have to account for cases where a "=" can be
        # inside of the output arguments. We could possibly cut down the split() to 1
        # but this will likely come up with other output in the future, so allowing for
        # more logic is probably a good idea here.
        split_by_eq = []

        for m in msg.split():
            if(len(m.split("=")) >= 2):
                _line_eq_split = m.split("=")

                # If this happens, we have an '=' in the string and need to handle it. This is
                # generally when base64 strings occur in the 'name' field of a file. This can
                # include a suffix (like =.tmp) or be the end (=)
                if len(_line_eq_split) >= 3:
                    _line_eq_split = [m.split("=")[0], m.split("=", 1)[1]]
                split_by_eq.append(_line_eq_split)

        for eq in split_by_eq:
           self.parsed_msg[eq[0]] = eq[1]

        return

    def parseToObj(self, msg=None):
        if not msg:
            msg = self.original

        self.parse(msg)

        if not self.parsed_msg:
            return None
        if not self.isAppArmorLog():
            return None
        #
        # Test if we have a known type, then return it as an object

        # XXX This could probably be improved, update it to be more
        # efficient and easier when we add new types.
        opfile = OpFile()
        if opfile.parse(self.parsed_msg):
            return opfile

        opcap = OpCapable()
        if opcap.parse(self.parsed_msg):
            return opcap

        opnet = OpNetwork()
        if opnet.parse(self.parsed_msg):
            return opnet

        opsignal = OpSignal()
        if opsignal.parse(self.parsed_msg):
            return opsignal

        opptrace = OpPtrace()
        if opptrace.parse(self.parsed_msg):
            return opptrace

        return None

    def isAppArmorMessage(self, msg = None):
        if not msg:
            return False
        return True

    def isAppArmorLog(self):
        if not self.parsed_msg:
            return False

        if 'apparmor' not in self.parsed_msg:
            return False

        if not self.parsed_msg["apparmor"]:
            return False

        return True

class ProcessRuleList:
    objlist = []
    name = ""

    def __init__(self, name):
        self.name = name
        self.objlist = []

        return

    def addObj(self, obj):
        self.objlist.append(obj)

    def isDuplicate(self, obj):
         # First the easy way, is the same rule in place?
         for rule in self.objlist:
             if rule.getDefaultRule() == obj.getDefaultRule():
                 # Duplicate rule
                 return True
         # No rule duplicate, see if we have other duplicates via the obj handlers
         # XXX This doesn't work yet, it needs to refer back to the whole list
         for rule in self.objlist:
             if rule.isDuplicate(obj):
                 # Duplicate
                 return True
         return False

#
# Primary front end for parsing log files
class LogParser:
    def __init__(self):
        self.profile_names = []
        self.entries = {}

    #
    # We keep this here, because it is used for key lookup in the tables below.
    # Don't move...even though it may be more intuitive.
    def normalizeProfileName(self, profile_name):
         # Sometimes these names come out like so:
         # /bin/path//null-24//null-7 etc
         # We normalize to the first "//"
         #
         # Also remove ' and ""
         profile_name = profile_name.strip("\"\'")
         idx = profile_name.find("//")
         if idx == -1:
             return profile_name.lstrip("/.")

         return profile_name[:idx].lstrip("/.")

    def getObj(self, key):
        return self.entries[key].objlist

    def parseLogfile(self, fi):
         with open(fi) as f:
             log_data = set(f.readlines())

         for message in log_data:
             aa_msg = ParseAppArmorMessage(message) # each log line.
             obj = aa_msg.parseToObj(message) # rule parsed from msg

             if not obj:
                 continue # Do nothing

             #
             # Handle per-process list appends
             norm_name = self.normalizeProfileName(obj.profile)
             # If no name exists, create it
             if norm_name not in self.profile_names:
                 self.profile_names.append(norm_name)

             #
             # Now add the rule list entry
             if norm_name not in self.entries:
                 self.entries[norm_name] = ProcessRuleList(norm_name)

            #
            # Now add the actual rule object itself
             if not self.isDuplicate(obj, self.entries[norm_name]):
                 self.entries[norm_name].addObj(obj)

             if hasattr(obj, 'getComment') and callable(hasattr(obj, 'getComment')):
                 self.entries[norm_name].addObj(obj.getComment())

    def getNameList(self):
        return self.profile_names
    def getObjList(self, name):
        if name in self.entries:
            return self.entries[name].objlist
        else:
            return None

    def isDuplicate(self, obj, rl):
        # First the easy way, is the same rule in place?
        for rule in rl.objlist:
            if rule.getDefaultRule() == obj.getDefaultRule():
                # Duplicate rule
                return True
        return False

    def SortLogList(self, profile_name):
        sortd = {}

        lt = self.entries[profile_name].objlist

        final_list = []

        for entry in lt:
            if entry.__class__.__name__ not in sortd:
                sortd[entry.__class__.__name__] = []
            sortd[entry.__class__.__name__].append(entry)

        for i in range(0, 150):
            for entry in sortd:
                if(i == sortd[entry][0].priority):
                    for e in sortd[entry]:
                        final_list.append(e)
        return final_list
