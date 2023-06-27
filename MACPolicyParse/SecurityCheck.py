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
import sys

from .ProfileTypes import *
from .Filter import *

#
# The checks in place here are for detection of security violations in AppArmor profiles.
#
# For example, we know that something like the below is unsafe:
#   /nvram2/test_script.sh wrix
#
# The rules here would detect this as a write or execute violation, fail script generation until
# it is resolved or an exception is added.
#
# The list of rules are defined as SecurityCheckRules() in a list at the end of this file.
#
# Since some rule types will require exceptions, those are handled in another list and by
# another object type that define the exception and track who signed off on it.
#
##
# To add a rule, add a SecurityCheckRule() to the list at the end of this file using the defined
#   structure. Be really careful to recognize certain fields, as they have specific meaning to how the
#   rule is parsed.
#
# To add an exception, the rule name is required as well as some other data, whihc you can see at the end.
#
# The handling of certain rule types, tags, and exceptions is likely incomplete and will need to grow as
# more are added. At some point, callbacks may be required where regex and simple matching isn't sufficient.
#
# We are concerned about files output from log entries AND profile entries,
# however it is most likely that manual profile entries will create these,
# so emphasis is put on checking those where possible.

#
# Define a security exception
# @rule_name - The rule that this exception applies to (e.g. CAPS_ALL)
# @exception_type - What the exception applies to (e.g. a specific line or a whole profile name)
# @exception_rege - Regex to match against the value specified by the type
# @descriptoin - Explain the exception briefly
# @signoff - Name of the person that signed off on the exception
class SecurityException:
    def __init__(self, rule_name, exception_type, exception_regex, description, signoff):
        self.rule_name = rule_name
        self.exception_type = exception_type
        self.exception_regex = exception_regex
        self.desc = description
        self.signoff = signoff

        return

#
# Define specific rules for security violations
#
# @objtype - String indicating what type of object (File, Capability, Signal, Ptrace)
# @rule - A list where rule[0] is the field in the object to check and rule[1] is a regex to check against.
# @raw - Check against the raw rule string as generated by getDefaultRule(). In this case, use @rule[1] as a regex and
#       @rule[0] is None
#
# The value of @rule[0] will depend on @objtype and define what is in @rule[1]. For instance, if @rule[0] is None, then
#   @rule[1] will treat @rule[0] as a regex to match against the entire line. If @rule[0] is "Permissions" and @objtype
#   is "File", then @rule[1] will be a list of permission characters to flag on (e.g. wx, mw). More of these will likely
#   need to be added over time.
#
class SecurityCheckRule:
    def __init__(self, objtype, name, rule, msg, raw=False):
        self.objtype = objtype
        self.rule = rule
        self.raw = raw
        self.msg = msg
        self.name = name

    # TODO: We need to add some kind of delegation back to the object types here,
    # as the list grows or changes. See the ProfileTypes.FileRule.isType() check
    # below for example
    def checkRule(self, rule):
        if self.raw == True or self.rule[0] == None:
            if re.search(self.rule[1], rule) == None:
                return False
            else:
                return True

        rule_tag = self.rule[0]
        rule_perms = self.rule[1]

        prule_type = self.getProfileType(rule)

        # Skip unsupported
        if prule_type == "None":
            return False

        if prule_type == "File" and self.objtype == "File":
            if rule_tag == "Permissions":
                perms = rule.lstrip().split()[1]
                for rule_perm_char in rule_perms:
                    if rule_perm_char not in perms:
                        return False
                return True
        # XXX The below aren't handled currently and need to be implemented when
        # needed, be sure to add them to getProfileType() below as well
        elif self.objtype == "Capability":
            return False
        elif self.objtype == "Signal":
            return False
        elif self.objtype == "Ptrace":
            return False
        else:
            print("WARNING: Unknown objtype passed into checkRule\n")
            return False

    def getProfileType(self, rule):

        if not rule or not rule[1]:
            print("WARNING: Empty rule passed to getProfileType")
            return "None"

        # TODO: This needs to be cleaned up so we can handle more than
        # just file rules. Ideally delegate back to their obj types, but
        # doing isType() wont work due to list validation
        file_perm_list = ['r', 'w', 'm', 'x', 'a', 'c', 'd']

        perm_result = [ele for ele in file_perm_list if(ele in rule[1])]
        if rule[0].startswith("/") and bool(perm_result):
            return "File"
        return "None"

class SecurityCheck:
    def __init__(self):
        self.error = False
        return

    def failed(self, rule, exe_name, check):
        print("\nSecurity violation found:")
        print("-> Profile: " + exe_name)
        print("--> Violation name: " + check.name)
        print("--> Violation description: " + check.msg)
        print("--> Line: " + rule + "\n")
        print("\n")

        self.error = True
        return

    # @profileobj - The OutputProfile object to scan for policy violations
    def checkProfile(self, profileobj):
        f = Filter("SecurityCheckList")
        check_list_tmp = f.loadFilterSet()

        for entry in check_list_tmp:
            check_list.append(SecurityCheckRule(entry.objtype, entry.name, entry.rule, entry.msg, entry.raw))

        # Operate on raw text rules
        for rule in profileobj.rule_list:
            for check in check_list:
                if check.checkRule(rule) == True:
                    # Rule match, check for exceptions
                    if self.checkExceptions(rule, check, profileobj) == True:
                        # We have an exception or no match, move on
                        continue
                    else:
                        # Rule match, no exception, error out
                        self.failed(rule, profileobj.exe_name, check)
                        continue
        if self.error == True:
            print("Rule generation failed due to security violations.\n")
            sys.exit(0)
        return

    # True on match
    def checkExceptions(self, rule, check, profileobj):
        f = Filter("SecurityExceptionList")
        e_list_tmp = f.loadFilterSet()

        for entry in e_list_tmp:
            exception_list.append(SecurityException(entry.rule_name, entry.exception_type, entry.exception_regex, entry.description, entry.signoff))

        # It would be more effective to index them as a dictionary but
        # then we lose the chance to have two named the same, so keep it this way
        #
        # Gather the list of exceptions that match our current name
        named_list = []
        for exc in exception_list:
            if exc.rule_name == check.name:
                named_list.append(exc)

        # Now check them
        #
        # Similar to the check types, the options here will likely need to grow
        # as need for different types of exceptions is found.
        for exc in named_list:
            # XXX Add check to make sure rule is a string
            if exc.exception_type == "ProfilePath":
                if re.search(exc.exception_regex, profileobj.exe_name) != None:
                    print("Exception Found")
                    return True
            elif exc.exception_type == "FullRegex":
                for rule in profile.rule_list:
                    if re.search(exc.exception_regex, rule) != None:
                        print("Exception Found")
                        return True
            else:
                print("ERROR: checkExceptions() exception_type is unknown.\n")
                sys.exit(0)
                return False
            return False
        return False

check_list = []

exception_list = []
