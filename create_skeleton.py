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

def create_skeleton(exe_path):
    pname = exe_path.rsplit("/")[-1]
    header = "profile " + pname + " " + exe_path

    return header + " {\n\n}"


exe_path = sys.argv[1]
out_path = sys.argv[2]

c = create_skeleton(exe_path)

fp = open(out_path, "w")
fp.write(create_skeleton(exe_path))
fp.close()

