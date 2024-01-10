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
import os

class Profile:
    '''
    Parses a profile file into its components to store to a
    rule_objlist.
    name = ""       # Name of the profile, taken from profile header
    path = ""       # Path for the exe under monitoring, taken from profile header
    filename = ""   # Path for the profile itself, taken from file path

    Parses capability, file, and profile header rules.
    '''

    name = ""
    rule_objlist = []

    def __init__(self, filename):
        self.filename = filename
        self.rule_objlist = []
        self.exe_path = ""
        self.name = ""

        self._subprofile_ctx = None
        self._cur_objlist = self.rule_objlist

        return

    def addRuleStr(self, rule):
        """
        Strips whitespace from the beginning of each profile line and
        passes it to be further parsed in addRuleList, where it will be
        categorized and added to rule_objlist.
        """
        rule = rule.rstrip()
        rule = rule.lstrip().split(" ")
        self.addRuleList(rule)
        return

    def addRuleList(self, rule):
        '''
        Checks rule string passed in to determine its type, parses the
        rule, and adds it to the object's rule_objlist.
        '''
        if type(rule) is not list:
            print("WARNING: Non-list passed to addRuleList")
            return
        if rule[0] == '' or rule[0] == '}':
            # Ignore these for now, make a class for them later XXX
            if rule[0] == '}' and self._subprofile_ctx != None:
                # This ends the subprofile state, null the state and
                # append the profile (remember all subprofile rules are
                # maintained within the TransitionProfileObject, so we
                # only append that
                self.rule_objlist.append(self._subprofile_ctx)
                self._subprofile_ctx = None
                self._cur_objlist = self.rule_objlist
            return

        # Ignore comments but not #includes
        if rule[0] == "#" and not rule[0] == "#include":
            return

        # modified "ew" to a list comprehension. should work well?
        rule = [a.strip("\n,}") for a in rule]
        if rule[0] == '':
            return

        # The final parsed rule should have no extra spaces in it, so we need to remove
        # any we find in the final rule list
        while('' in rule):
            rule.remove('')


        if FileRule().isType(rule):
            fr = FileRule()
            fr.parse(rule)
            self._cur_objlist.append(fr)
            return
        elif CapableRule().isType(rule):
            cr = CapableRule()
            cr.parse(rule)
            self._cur_objlist.append(cr)
            return
        #
        # Two part detection: Our current profile header
        # and subprofiles
        elif ProfileHeaderRule().isType(rule):
            if self._cur_objlist != self.rule_objlist:
                # Skip subprofile
                return

            pr = ProfileHeaderRule()
            pr.parse(rule)
             # Profile headers can indicate a subprofile, if self.name and path are
             # set, then it's like what we're seeing
             #
             # This marks the beginning of a subprofile state, where
             # whatever entries parsed from here are put in the context
             # of a subprofile. This starts with the identification of
             # the profile header and ends when a } is enocuntered
            if self.name != "" or self.exe_path != "":
                self._subprofile_ctx = TransitionProfileRule(self.name, self.exe_path)
                #self._subprofile_ctx.parse(rule)
                self._cur_objlist = self._subprofile_ctx.profile_ruleobjs

                # XXX We should add some validation that self.exe_path shows up in
                # the profile

                # We do not append here, rather when a close bracket is
                # encountered
                return
            self.name = pr.name
            self.exe_path = pr.path

            self.rule_objlist.append(pr)

            return
        elif SignalRule().isType(rule):
            sr = SignalRule()
            sr.parse(rule)
            self._cur_objlist.append(sr)

            return
        elif PtraceRule().isType(rule):
            ptr = PtraceRule()
            ptr.parse(rule)
            self._cur_objlist.append(ptr)
        elif IncludeRule().isType(rule):
            ptr = IncludeRule()
            ptr.parse(rule)
            self._cur_objlist.append(ptr)
        else:
            print("WARNING: Unknown rule type for rule. Raw rule added.")
            print("Raw rules are not validated, parsed, or updated. Please file")
            print("An issue with the contents of the rule below so we can implement")
            print("support for this rule type.")
            print("Rule: " + str(rule))

            ptr = RawRule()
            ptr.setRawRule(rule)
            self._cur_objlist.append(ptr)

            return

#
# Primary front end interface for parsing existing profiles
class ProfileParser:
    def __init__(self):
        self.names_list = []
        self.entries = {}

    def loadProfile(self, path, filename):
        print("Loading profile from file: " + path + filename)

        if os.path.isdir(path + "/" + filename):
            print("ERROR: Path is directory, skipping")
            print("Path: " + path + filename)
            return

        if filename in self.names_list:
            print("****** MANUAL EDIT REQUIRED ******")
            print("*: loadProfile found a duplicate profile name, skipping")
            print("* Profile path 1: " + filename)
            print("* Duplicate profile names will NOT be merged, manually merge them and delete the duplicate.")
            print("************")
            return

        cp = Profile(filename)

        with open(path + "/" + filename, "r") as fp:
            for line in fp.readlines():
                cp.addRuleStr(line)

            self.names_list.append(cp.name)
            self.entries[cp.name] = cp

    def loadProfilesDir(self, path, skip):
        for x in os.listdir(path):
            if skip and x in skip:
                print("Skipping profile due to skip_profile arg: " + x)
                continue

            self.loadProfile(path, x)

    # XXX Add more getters here so that the underlying objects are opaque
    def getEntryName(self, key):
        return self.entries[key].name

    def getObj(self, key):
        return self.entries[key].rule_objlist

    def getObjList(self, name):
        if name in self.entries:
            return self.entries[name].rule_objlist
        else:
            return None

    def getNameList(self):
        return self.names_list

    def getFilename(self, name):
        if name in self.entries:
            return self.entries[name].filename
        else:
            return None

    def getPath(self, name):
        if name in self.entries:
            return self.entries[name].exe_path
        else:
            return None
