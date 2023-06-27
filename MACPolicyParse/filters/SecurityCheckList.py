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

 #
 # These follow this structure
 # 0 - Resource type (Capability, File, Ptrace, etc)
 # 1 - Name - This must be a unique name for this alert/exception
 # 2 - Check - This follows this structure: (CheckType, CheckData), where data is varied depending on what the type is
 # 3 - Msg/Desc - Message or description for this alert
 # 4 - Raw - Only used if the detection is a raw regex against the entire line (CheckType would be None in this case)
 #
 # For example:
 # SecurityCheckRuleTemp("Capability", "CAP_DACOVERRIDE", (None, "/.*dac_override.*/"), "DAC_OVERRIDE allowed", True),
 #
class SecurityCheckRuleTemp:
    def __init__(self, objtype, name, rule, msg, raw=False):
        self.objtype = objtype
        self.rule = rule
        self.raw = raw
        self.msg = msg
        self.name = name

class SecurityCheckList:
    filter_list = {}

    def __init__(self):
        self.filter_list = {
         #    SecurityCheckRuleTemp("Capability", "CAP_DACOVERRIDE", (None, "/.*dac_override.*/"), "DAC_OVERRIDE allowed", True),
         }
