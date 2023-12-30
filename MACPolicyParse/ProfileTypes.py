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
from .Diff import *

class ProfileBase:
    rule_type = ""
    priority = 0

    def __init__(self):
        return

    def isType(self, rule):
        print("WARNING: Pure virtual call to ProfileBase.isType")
        return False

    def validateList(self, rule, size):
        if type(rule) is not list:
            print("WARNING: Non-list passed into validateList")
            return False

        if size != None and len(rule) != size:
            # This function is called for identification of types, which
            # means this is a non-error since it'll be called on everything
            #print("validateList len failure.")
            return False

        return True

    def getDefaultRule(self):
        print("WARNING: Pure virtual to Profile.getDefaultRule")
        return "# PURE VIRTUAL FAIL"

    def isDuplicate(self):
        return False

# Policy header
class ProfileHeaderRule(ProfileBase):
    name = ""
    path = ""
    flags = ""

    complain_mode_str = "complain"
    audit_mode_str = "audit"                        # Not implemented
    enforce_mode_str = "enforce"
    mediate_deleted_str = "mediate_deleted"         # Not implemented
    attach_disconnected_str = "attach_disconnected" # Not implemented
    chroot_relative_str = "chroot_relative"         # Not implemented

    def __init__(self):
        ProfileBase.__init__(self)
        self.priority = 100
        return

    def isType(self, rule):
        if not ProfileBase.validateList(ProfileBase(), rule, None):
            return False
        if rule[0].startswith("profile"):
            return True

        return False

    def parse(self, rule):
        # We don't validate the length here, because it could be variable

        if not self.isType(rule):
            return None

        # Some profiles have excessive spacing, remove those to avoid problems with
        # naming.
        while('' in rule):
            rule.remove('')

        self.name = rule[1]
        self.path = rule[2]
        self.flags = rule[3]
        # XXX Add flags

    #
    # This could be better, but profiles are a special case, hence why
    # they are handled here instead of getDefaultRule()
    def genProfileHeader(self, name, path, mode="complain"):
        self.profile_type.name = name
        self.profile_type.path = path
        # Ignore flags for now

        flags = f"flags=({mode})"
        return f"profile {name + path + flags}{{\n"

    def getDefaultRule(self):
        # Ignore the profile rules
        return None

# These expect a split list for each rule
# e.g. ['/foo/bar', 'rw']
class FileRule(ProfileBase):
    filename = ""
    permissions = ""
    handled = False

    def __init__(self):
        ProfileBase.__init__(self)
        self.priority = 20 #XXX Make a single class for these so wthey can be uniform for logs and profiles
        return

    def getDefaultRule(self):
        # XXX Validate

        if ".so" in self.filename:
            self.filename = self.fixLibraryVersions(self.filename)

            if self.filename == "" or self.filename == None:
                # Empty spaces are cleaned up elsewhere
                return ""

        return self.filename + " " + self.permissions

    def isType(self, rule):
        if not ProfileBase.validateList(ProfileBase(), rule, 2):
            return False

        # XXX Possibly incomplete
        # XXX This currently doesn't handle cases whee the filename doesn't start with a slash
        file_perm_list = ['r', 'w', 'm', 'x', 'a', 'c', 'd']
        perm_result = [ele for ele in file_perm_list if(ele in rule[1])]
        if rule[0].startswith("/") and bool(perm_result):
            return True

        return False

    def parse(self, rule):
        if not ProfileBase.validateList(ProfileBase(), rule, 2):
            return None

        if not self.isType(rule):
            return None

        # XXX Add more validation here
        self.filename = rule[0]

        self.permissions = rule[1].strip("\n,") # XXX End of the line has to have ,\n stripped

    # If we keep running into cases where profile changes need to be made in a sweeping manner,
    # we may want to add an API for doing this similar to the securitycheck rules
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

        if not re.fullmatch("[A-Za-z\+\_\-0-9\.\*]+\.so([\s\.\0-9\*]+)?", os.path.basename(filename)):
            return filename

        if filename == "/lib*.so*":
            # This is to remove an old, bad entry that was inserted due to a bug
            return ""

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

        # Don't remove existing .so* sequences
        if ".so*" in lib_name:
            new_rule += "*"

        if ".so.*" in lib_name:
            new_rule = new_rule.replace(".so.*", ".so")
            new_rule += "*"

        self.handled = True

        # This can happen if there is a bug here or a format we do not expect, it's not
        # very likely, but is possible and it's safer to exit
        if new_rule == "/lib*.so*":
            print("ERROR: fixLibraryVersions() created an invalid entry due to a bug")
            print("-> Original filename: ")
            print(filename)
            print("First, please verify there are no \"lib*.so*\" entries in the input profiles.")
            print("If there are, please remove them and try again. If there are not, then ")
            print("please submit the filename above as a bug report with this error.")
            sys.exit(0)

        return new_rule

    def diff(self, obj_list):
        result = 0

        for entry in obj_list:
            if isinstance(entry, FileRule):
                if entry.filename == self.filename:
                    # Same filename means we have some sort of match
                    if entry.permissions == self.permissions:
                        # Identical
                        return DiffResult(1, entry, self)
                    else:
                        # Different permissions
                        return DiffResult(2, entry, self, uuid=self.filename)
        return DiffResult(0, None, self)

# XXX This needs to handle cases where it's just 'capability,', which allows all
#   XXX Mainly warn on this
class CapableRule(ProfileBase):
    capability = ""

    def __init__(self):
        ProfileBase.__init__(self)
        self.priority = 10
        return

    def getDefaultRule(self):
        # XXX validate
        return "capability " + self.capability

    def isType(self, rule):
        if not ProfileBase.validateList(ProfileBase(), rule, 2):
            return False

        if rule[0].startswith("capability"):
            return True

        return False

    def parse(self, rule):
        if not ProfileBase.validateList(ProfileBase(), rule, 2):
            return None

        if not self.isType(rule):
            return None

        # XXX Add validation that the capability is in the cap list
        self.capability = rule[1].strip("\n,")

    def diff(self, obj_list):
        for entry in obj_list:
            if isinstance(entry, CapableRule):
                if entry.capability == self.capability:
                    return DiffResult(1, entry, self)
        return DiffResult(0, None, self, uuid=self.capability)

class SignalRule(ProfileBase):

    def __init__(self):
        ProfileBase.__init__(self)
        self.priority = 11
        return

    def getDefaultRule(self):
        # XXX validate
        return "signal"

    def isType(self, rule):
        rule =  [ele for ele in rule if ele.strip()]
        if not ProfileBase.validateList(ProfileBase(), rule, 1):
            return False
        if rule[0].startswith("signal"):
            return True

        return False

    def parse(self, rule):
        if not ProfileBase.validateList(ProfileBase(), rule, 1):
            return None

        if not self.isType(rule):
            return None

    def diff(self, obj_list):
        for entry in obj_list:
            if isinstance(entry, SignalRule):
                return DiffResult(1, entry, self)
        return DiffResult(0, None, self)

class PtraceRule(ProfileBase):

    def __init__(self):
        ProfileBase.__init__(self)
        self.priority = 12
        return

    def getDefaultRule(self):
        # XXX validate
        return "ptrace"

    def isType(self, rule):
        rule = [ele for ele in rule if ele.strip()]
        if not ProfileBase.validateList(ProfileBase(), rule, 1):
            return False

        if rule[0].startswith("ptrace"):
            return True

        return False

    def parse(self, rule):
        if not ProfileBase.validateList(ProfileBase(), rule, 1):
            return None

        if not self.isType(rule):
            return None

    def diff(self, obj_list):
        for entry in obj_list:
            if isinstance(entry, PtraceRule):
                return DiffResult(1, entry, self)
        return DiffResult(0, None, self)
#
# This is when we have a profile within a profile
class TransitionProfileRule(ProfileBase):
        def __init__(self, name, exe_path):
            ProfileBase.__init__(self)
            self.priority = 13

            self.profile_header = ""
            self.profile_ruleobjs = []

            self.name = name
            self.exe_path = exe_path
            return

        # Unique to this class
        def addSubRule(self, obj):
            self.profile_ruleobjs.append(obj)
            return

        def isType(self, rule):
            rule = [ele for ele in rule if ele.strip()]
            if not ProfileBase.validateList(ProfileBase(), rule, 1):
                return False
            return rule[0].lstrip().startswith("profile")


        def parse(self, rule):
            # The header parsing is handled by the header type, so this
            # should never be reached (see generateOutputProfiles())
            print("WARNING: TransitionProfileRule:parse() called.\n")
            return None

        #
        # Normally, this would return a single rule, however in this
        # case we have a number of rules associated with the profile
        # and the brackets, we build all of that here and return it
        # as a string for inclusion in the final profile
        def getDefaultRule(self):
            rule_str = ""
            # Start with the header
            rule_str += "   profile " + self.name + " " + self.exe_path
            rule_str += " {\n"

            for r in self.profile_ruleobjs:
                rule_str += "       " + r.getDefaultRule() + ",\n"
            rule_str += "   }\n"

            return rule_str

class IncludeRule(ProfileBase):

    def __init__(self):
        ProfileBase.__init__(self)
        self.priority = 120
        self.include_path = ""

        return

    def getDefaultRule(self):
        # XXX validate
        return "#include " + self.include_path

    def isType(self, rule):
        rule = [ele for ele in rule if ele.strip()]
        if not ProfileBase.validateList(ProfileBase(), rule, 2):
            return False

        if rule[0] == ("#include"):
            print("Include rule found.")
            return True

        return False

    def parse(self, rule):
        if not ProfileBase.validateList(ProfileBase(), rule, 2):
            return None

        if not self.isType(rule):
            return None

        self.include_path = rule[1]
        print("Include path: " + rule[1])
