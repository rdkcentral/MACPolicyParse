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
# This handles returning diffed profile data from the
# profile handlers to the main output routine
class DiffResult:
    result = -1
    old_obj = None
    new_obj = None
    uuid = None # This is for finding removed entries (filename for files, cap for cap, etc)

    def __init__(self, result, old_obj, new_obj, uuid=None):
        self.result = result
        self.old_obj = old_obj
        self.new_obj = new_obj
        self.uuid = uuid
