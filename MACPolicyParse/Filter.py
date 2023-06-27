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

import sys

#
# A very generic way of moving filters and SecurityCheck rules into their own files.
#
# This basically just imports a module then returns the list of filters provided by the class via
# the filter_list in the parent class
#
# We do this instead of CSV files both to simplify parsing but also to allow callbacks and other
# functionality that may be needed in future iterations.
class Filter:
    def __init__(self, filter_name):
        self.filter_name = filter_name

        self.loadFilterSet()

    def loadFilterSet(self):
        sys.path.append("MACPolicyParse/filters/")
        mod = __import__(self.filter_name, globals(), locals(), [], 0)

        filter_cls = getattr(mod, self.filter_name)
        cls = filter_cls()
        return cls.filter_list
