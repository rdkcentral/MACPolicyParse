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

from .LogParser import *
from datetime import datetime
from .ProfileTypes import *
import re
from .LogTypes import *
from .ProfileParser import *
#
# This is the container class for all of the other rule types: those from files and those from log entries
#
# As such, it should be the primary frontend for:
# 1. Log parsing
# 2. Profile loading
#
# The idea being that this class is consumed by whatever profile generators we have without having to be
# familar with the input data sources.
#
class RuleList:
    file_rule_dict = {}

    def __init__(self, f=None):
        self.log_parser = LogParser()
        self.file_rule_dict = {}

        self.pp = ProfileParser()

        if f:
            self.parseLogfile(f)

    #
    # Primary front end for inserting data related to existing profiles
    def loadExistingProfiles(self, profile_path, skip):
        # Load existing profiles
        self.pp.loadProfilesDir(profile_path, skip)

        for key in self.pp.names_list:
            print("Initializing for profile: " + self.pp.entries[key].name)
            self.addFileList(self.pp.entries[key], self.pp.entries[key].rule_objlist)

    #
    # Primary frontend for log parsing
    def parseLogfile(self, f):
        self.log_parser.parseLogfile(f)

    def getLogNames(self):
        return self.log_parser.getNameList()

    def getLogObjList(self, name):
        return self.log_parser.getObjList(name)

    def getProfileNames(self):
        return self.pp.getNameList()

    def getProfilePath(self, name):
        return self.pp.getPath(name)

    def getProfileObjList(self, name):
        return self.pp.getObjList(name)

    def addFileList(self, profile, rule_list):
        # At one point here we did this:
        #   norm_filename = profile.name.replace(".", "/").lstrip("/.")
        # profile.name should report the . name, not
        # including slashes. If we run into future problems with profile keys
        # not matching properly, this is a good place to start looking
        norm_filename = profile.name.lstrip("\.")

        if norm_filename not in self.log_parser.profile_names:
            self.log_parser.profile_names.append(norm_filename)

        if norm_filename not in self.file_rule_dict:
            self.file_rule_dict[norm_filename] = rule_list
            return

        print("WARNING: addFileEntry has duplicate filenames, one was discarded") # XXX handle this better
        return

