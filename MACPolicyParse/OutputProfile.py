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

from .ProfileParser import *
from .ProfileTypes import *
from .RuleList import *
from .SecurityCheck import *
import os

class OutputProfile:
    def __init__(self, name, filename=""):
        self.name = name
        self.filename = filename
        self.exe_name = ""

        self.profile_entries = []
        self.log_entries = []

        self.rule_list = []
        self.raw_dict = {}

        self.include_list = []
        self.include_count = 0

    def getProfileStamp(self):
        now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        return f'# Automated profile generated on {now}\n'

    def getProfileHeader(self):
            if self.name == "" or self.exe_name == "":
                # This shouldn't happen but the log files are potentially mangled
                return ""
            return f"profile {self.name} {self.exe_name} flags=(complain) {{\n"

    def addRule(self, rule, raw_obj=None):
        # XXX Type check
        self.rule_list.append(rule)
        self.raw_dict[rule] = raw_obj

    def getRuleList(self):
        return self.rule_list

class OutputInclude:
    def __init__(self, name, regex):
        self.name = name
        self.filename = ""
        self.regex = regex

        self.rule_list = []
        self.keydict = {}

        self.include_line = "include " + name

    def parseForIncludes(self, opl):
        threshold = 3
        include_rules = []

        for op in opl:
            for rule in op.getRuleList():
                if rule in self.keydict:
                    self.keydict[rule] += 1
                else:
                    self.keydict[rule] = 1

        for entry in self.keydict:
            if self.keydict[entry] >= threshold:
                include_rules.append(entry)

        for op in opl:
            for entry in include_rules:
                if entry in op.getRuleList():
             #       print("Removing " + entry + " from " + op.name)
                    op.rule_list.remove(entry) #XXX Make this official somehow
                    if not self.include_line in op.getRuleList():
                        op.rule_list.insert(0, self.include_line)
                    op.include_count += 1

            print(f"For profile {op.name} consolidated {str(op.include_count)} entries into include files")

        return include_rules


class GenProfiles:
    def __init__(self, rl=None):
        if not rl:
            self.rl = RuleList()
        else:
            self.rl = rl

    def ParseExistingProfiles(self, profile_path, skip):
        self.rl.loadExistingProfiles(profile_path)

    def ParseLogFile(self, path):
        self.rl.parseLogfile(path)

    def GetLogEntriesForName(self, name):
        return self

    def GetProfileEntriesForName(self, name):
        return None

    def GetNames(self):
        nl = []

        for pn in self.rl.getProfileNames():
            if pn not in self.rl.getLogNames():
                nl.append(pn)
        for pn in self.rl.getLogNames():
            nl.append(pn)
        return nl

    #
    # Initializes profile metadata
    def initOutputProfile(self, op):
            op.profile_entries = self.GetProfileEntriesForName(op.name)
            op.log_entries = self.GetLogEntriesForName(op.name)
            op.exe_name = self.rl.getProfilePath(op.name)

            if not op.exe_name:
                print("**** MANUAL EDIT REQUIRED ****")
                print("WARNING: No profile filename found for profile name " + op.name)
                print("Using profile name as filename.\n")
                print("Edit required: Change process path in the profile header to match exe path")
                print("****************")
                op.exe_name = op.name

            if op.filename == "":
                op.filename = op.exe_name.replace("/", ".")
                if op.filename and op.filename[0] == '.':
                    op.filename = op.filename[1:]
                print("* Automatic profile path generation: ")
                print(f"** For profile exe path \"{op.exe_name}\" using \"{op.filename}\" as profile filename.")
    #
    # This initializes the list of OutputProfile objects, along with triggering duplicate
    # detections
    def generateOutputProfiles(self):
        opl = []

        for name in self.GetNames():
            op = OutputProfile(name)
            self.initOutputProfile(op)

            # Now start accessing the rule lists themselves, starting with the profiles
            # XXX Change this to use OP methods instead of the RL
            profilelist = []
            loglist = []

            if self.rl.getProfileObjList(name):
                profilelist = self.deDuplicate_Profile(self.rl.getProfileObjList(name))
            if self.rl.getLogObjList(name):
                loglist, profilelist = self.deDuplicate_Log(self.rl.getLogObjList(name), profilelist)

            for entry in profilelist:
                op.addRule(entry.getDefaultRule(), entry)

            for entry in loglist:
                op.addRule(entry.getDefaultRule(), entry)

            # XXX This could possibly be moved to occur prior to adding rules, but for now
            # we just postprocess the entire profile.
            sc = SecurityCheck()
            sc.checkProfile(op)

            opl.append(op)
        return opl

    #
    # This should be the primary frontend, as it returns text profiles based on the OP list
    def generatePolicyFileList(self):
        opl = []
        opli = self.generateOutputProfiles()
        cur_dict = {}

        # Leave includes dsiabled for now
        #oi = OutputInclude("All", None)
        #oi.parseForIncludes(opli)

        for op in opli:
            cur_profile = op.getProfileStamp()
            header = op.getProfileHeader()
            if header == "":
                # Error
                print("Empty profile name/header fields.")
                continue
            cur_profile += header

            cur_list = op.getRuleList()
            # TODO: Test with various outputs to ensure we get the sorting we want. But this works for really basic tests.
            cur_list.sort(reverse=True, key=lambda p: (-p.count(os.path.sep), p))

            for cur_rule in cur_list:
                # This is removed because it does partial matches, revisit
                # if we find ourselves having dupe problems
                #if cur_rule in cur_profile:
                #    continue
                if cur_rule == "":
                    continue
                # Subprofiles are handled differently, so no spacing or
                # comma
                if cur_rule.split()[0] == "profile":
                    cur_profile += cur_rule
                else:
                    cur_profile += "    " + cur_rule + ",\n"

            cur_profile += "}"

            if op.filename == "":
                print("**** MANUAL EDIT REQUIRED ****")
                print("WARNING: Empty filename, appending to lostandfound")
                print("********")
                cur_dict["filename"] = "lostandfound"
            else:
                cur_dict["filename"] = op.filename

            cur_dict["profile"] = cur_profile

            opl.append(cur_dict)
            cur_dict = {}

        return opl

    def isInLogList(self, entry, loglist):
        return False
    def deDuplicate_Profile(self, profile_list):
        # Do nothing atm since it's assumed profiles wont' have duplicate entries, whcih is a bad
        # assumption

        return set(profile_list)

    # It would be better practice to delegate this to the classes somehow, or at least part of it
    # XXX
    # Returns the new de-duplicated LOG list, profile duplicates will still exist
    def deDuplicate_Log(self, rule_list, profile_list):
        file_dict = {}
        new_list = []

        for entry in rule_list:
            # We really only care about files
            #
            # We keep a dictionary of each file found. If a duplicate is found, we update the
            # permissions.
            if isinstance(entry, OpFile):
                new_mask = entry.requested_mask.strip("\"")

                # First, we check to see if we have a profile entry for this file
                for s in profile_list:
                    if not isinstance(s, FileRule):
                        continue # We just care about the file rules here, others are deduped earlier

                    if s.filename == entry.name:
                        # Yes, so we use the profile entry to track the permissions and ignore future entries
                        if new_mask in s.permissions:
                            break
                        new_mask += s.permissions
                        profile_list.remove(s)

                        break

                if entry.name in file_dict:
                    # Handle collision by updating requested_mask, then removing the entry from the list
                    if new_mask in file_dict[entry.name].requested_mask:
                        continue
                    file_dict[entry.name].requested_mask += new_mask
                else:
                    # New file
                    for c in new_mask:
                        if not c in entry.requested_mask:
                            entry.requested_mask += c
                    file_dict[entry.name] = entry
            elif isinstance(entry, OpCapable):
                # TODO: make this more gooder?
                file_dict[entry.capname] = entry
            elif isinstance(entry, OpNetwork):
                if not entry.family + entry.sock_type in file_dict:
                    file_dict[entry.family.strip("\"") + entry.sock_type.strip("\"")] = entry
            elif isinstance(entry, OpComment):
                file_dict[entry.getDefaultRule().strip("\"")] = entry
            elif isinstance(entry, OpSignal):
                if not "signal" in file_dict:
                    file_dict["signal"] = entry
            elif isinstance(entry, OpPtrace):
                if not "ptrace" in file_dict:
                    file_dict["ptrace"] = entry

        for entry in file_dict:
            new_list.append(file_dict[entry])

        return new_list, profile_list

    # Finally, just do a basic text search. If it exists, we remove it.
    def deDuplicate_Text(self, profile_text):
        return None

    def diffProfiles(self, old_list):
        old_rl = old_list.rl
        new_rl = self.rl

        old_names = old_rl.getProfileNames()
        new_names = new_rl.getProfileNames()

        new_profile_names = []
        existing_profile_names = []
        profile_changes = {}
        new_profile_entries = {}
        removed_profile_entries = {}

        # Construct a list of profiles that are brand new, if any
        for cur_name in new_names:
            if not cur_name in old_names:
               new_profile_names.append(cur_name)
            else:
               existing_profile_names.append(cur_name)

        # For new profiles, just output the whole thing as new
        print("******** Profile Diff Results *********")
        print("\nWarning: Diff functionality is beta and may not be reliable, please")
        print(" confirm results with 'diff -u -p' and report inconsistencies.")
        print("\nResults: ")
        for name in new_profile_names:
            # XXX I'd like to print these out eventually but for now that is tricky
            print("New profile : " + name)

        #
        # Now the meat of the diff, we have to compare each object from the old list
        # to the one in the new list. This may create problems with the way we dedup but
        # prevens us from having to generate profiles, re-parse, then diff.
        for cur_name in existing_profile_names:
            # cur_obj is going to be a list of ProfileType objects (signal, file, etc)
            cur_obj = new_rl.getProfileObjList(cur_name)
            old_objlist = old_rl.getProfileObjList(cur_name)

            for cur_newentry in cur_obj:
                # Now we delegate the process of finding the entry in the list back to the type
                # for every list entry
                # 0 - No entry
                # 1 - Identical entry found
                # 2 - Entry found but changed
                dr = cur_newentry.diff(old_objlist)
                result = dr.result

                # Entry in the new profile, but not the old
                if result == 0:
                    # There is a weird case here where files can be mutated during
                    # getDefaultRule(), so the filename == filename condition is met
                    # but the end result is actually different, so we have to make
                    # a weird exception here

                    new_fname = cur_newentry.getDefaultRule().split(" ")[0].replace('*', '')

                    for entry in old_objlist:
                        if isinstance(entry, FileRule):
                            if entry.filename.replace('*', '') == new_fname:
                                # Now we have an entry that hits the rough match criteria, so its' not unique
                                result = 2
                                dr.uuid = new_fname
                                dr.result = 2
                                dr.old_obj = entry

                    if result == 0:
                        if not cur_name in new_profile_entries:
                            new_profile_entries[cur_name] = []

                        new_profile_entries[cur_name].append(cur_newentry)

                # Identical entry
                if result == 1:
                    for entry in old_objlist:
                        if entry.filename == cur_newentry.filename:
                            old_objlist.remove(entry)

                # Exists in both but with differences
                if result == 2:
                    if not cur_name in profile_changes:
                        profile_changes[cur_name] = []
                    profile_changes[cur_name].append([cur_newentry, dr])

                    # At this point, this really only applies to files. If that
                    # changes then we should add a uuid to each profile type
                    # also and compare those XXX
                    for entry in old_objlist:
                        if dr.uuid != None:
                            if isinstance(entry, FileRule):
                                if dr.uuid.replace('*', '') == entry.filename.replace('*', ''):
                                    old_objlist.remove(entry)


            # This is technically leftover entries, but it should be empty
            for entry in old_objlist:
                if not cur_name in removed_profile_entries:
                    removed_profile_entries[cur_name] = []
                removed_profile_entries[cur_name].append(entry)

            print("Diff for profile: " + cur_name)
            print("Profile changes: ")
            if cur_name in profile_changes:
                for n in profile_changes[cur_name]:
                    print(n[1].old_obj.getDefaultRule() + " -> " + n[0].getDefaultRule())

            print("New profile entries: ")
            if cur_name in new_profile_entries:
                for n in new_profile_entries[cur_name]:
                    print(n.getDefaultRule())

            print("Removed entries: ")
            if cur_name in removed_profile_entries:
                for d in removed_profile_entries[cur_name]:
                    print(d.getDefaultRule())

        return

