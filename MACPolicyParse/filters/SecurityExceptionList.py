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
 # @rule_name - Rule name that matches one in check_list
 # @exception_type - What field to match (ProfilePath, FullRegex)
 # @exception_regex - The regex to match against the prev field
 # @description - Briefly description of the exceptoin
 # @signoff - Name of the person signing off on the exception
class SecurityExceptionTmp:
    def __init__(self, rule_name, exception_type, exception_regex, description, signoff):
        self.rule_name = rule_name
        self.exception_type = exception_type
        self.exception_regex = exception_regex
        self.description = description
        self.signoff = signoff

class SecurityExceptionList:
    filter_list = {}

    def __init__(self):
        self.filter_list = {
            SecurityExceptionTmp("CAP_ALL", "ProfilePath", "/.*/", "Allow all capabilities", "TestDoNotDeploy"),
         }
