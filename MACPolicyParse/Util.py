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

GlobalLogger = None

# Global logger for tracking warnings, errors, and security violations.
#
# Basically provides a cleaner, easier to trace interface that using print(), also
# allows us to output details to a file rather than just to the console
#
# Warning example:
# -            print("ERROR: Path is directory, skipping")
# -            print("Path: " + path + filename)
# +            GlobalLogger.addWarning("ProfileParser", "LoadDir", "Specified path is a directory, skipping: " + path + filename)
#
# Error example:
# -        print("WARNING: Pure virtual to Profile.getDefaultRule")
# +        GlobalLogger.addError("ProfileBaseOp", "Pure Virtual", "Pure virtual call to base_op: isDuplicate", True)


class Logging:
    def __init__(self, write_dir):
        self.manual_edit_buf = {}

        self.warning_buffer = {}
        self.error_buffer = {}

        global GlobalLogger = self

    def addWarning(self, profile, name, message):
        if not self.warning_buffer[profile]:
            self.warning_buffer[profile] = []

        self.warning_buffer[profile].append(name + " : " + msg)

    def outputWarnings(self):
        print("******** WARNINGS ************\n")

        for warn in self.warning_buffer:
            print(warn + " : " + self.warning_buffer[profile])

        print("******** END WARNINGS ************\n")

        return

    def addError(self, profile, name, message, exit=True):
        if not self.error_buffer[profile]:
            self.error_buffer[profile] = []

        self.error_buffer[profile].append(name + " : " + msg)

        if exit == True:
            self.outputAll()
            print("\n")
            print("Profile generation failed due to fatal errors.\n")
            sys.exit(0)

    def outputErrors(self):
        print("********* FATAL ERRORS *********\n")
        for err in self.error_buffer:
            print(err + " : " + self.error_buffer[profile])

        print("******** END ERRORS **********\n")

        return

    # Track lines that need to be manually edited. These aren't warnings or
    # errors, just things that need to be revisited and cleaned up
    def addManualEdit(self, name, msg):
        self.manual_edit_buf.append(name + " : " + msg)

    def outputManualEdits(self, fp):
        if fp == None:
            # To console

            for msg in self.manual_edit_buf:
                print("= " + msg)

            print("******** END MANUAL EDITS *********")

    def outputAll(self):
        self.outputManualEdits(None)
        self.outputWarnings()
        self.outputErrors()

        return
