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

import argparse

import shutil
import os
import sys
from MACPolicyParse import GenProfiles

def create_profile(proc_path, profile_path):
    if proc_path[0] != "/":
        print("Fully qualified path to the process is required.")
        sys.exit(0)

    profile_filename = proc_path.replace("/", ".")[1:]

    profile = "profile " + profile_filename + " " + proc_path + " flags=(complain, attach_disconnected) {\n}"

    fp = open(profile_path + "/" + profile_filename, "w")
    fp.write(profile)
    fp.close()

def main():
    if sys.version_info < (3, 0):
        sys.stdout.write("Please use python3, python 2.x is not supported.\n")
        return -1

    ap = argparse.ArgumentParser()
    # XXX We need to add more checks on these
    ap.add_argument("--profile_dir", help="Directory containing current profiles", required=False)
    ap.add_argument("--log_file", help="Single log file for parsing", required=False)
    ap.add_argument("--display", help="Prints generated files", action="store_true", default=True)
    ap.add_argument("--write", help="Writes generated profiles to <dst>")
    ap.add_argument("--create", help="Write a profile for <proc path>")
    ap.add_argument("--diff", help="Compare the original profile and the new one", action="store_true")
    ap.add_argument("--skip_profile", help="Skip this profile and copy it to the write dir unmodified", required=False)

    args = ap.parse_args()

    if args.create:
        create_profile(args.create, args.write)
        return 0

    if not args.profile_dir :
        print("--profile_dir is required.")
        return -1

    op = GenProfiles()

    op.ParseExistingProfiles(args.profile_dir, args.skip_profile)

    if args.log_file:
        op.ParseLogFile(args.log_file)

    dlist = op.generatePolicyFileList()

    for entry in dlist:
        if not args.write:
                print("Profile name: " + entry["filename"])
                print(entry["profile"])
        else:
            fp = open(args.write + entry["filename"], "w")
            fp.write(entry["profile"])
            fp.close()


    if args.diff:

        # Handle loading the new profiles
        # This is not super clean but we can try to revise later
        # Write the current profiles to a profile, load/parse under
        # a new output context, then compare them to the old
        # output context
        #
        # XXX make sure generatePolicyFiles() doesnt change OP state
        os.mkdir("./_aa_diff_tmp")
        for entry in dlist:

            fp = open("_aa_diff_tmp/" + entry["filename"], "w")
            fp.write(entry["profile"])
            fp.close()

            shutil.copyfile(args.skip_profile, args.write + os.path.basename(args.skip_profile))

        new_op = GenProfiles()
        new_op.ParseExistingProfiles("_aa_diff_tmp/")

        # Handle loading the old profiles
        old_op = GenProfiles()
        old_op.ParseExistingProfiles(args.profile_dir)

        new_op.diffProfiles(old_op)

        # Cleanup
        shutil.rmtree("./_aa_diff_tmp")

if __name__ == "__main__":
    sys.exit(main())
