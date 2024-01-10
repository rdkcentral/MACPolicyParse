# Mandatory Access Control Policy Parser / Generator
A tool for automatically updating AppArmor profiles based on data from provided kernel logs. 

The tool takes two primary data sources:
 * A kernel log containing AppArmor kernel messages (complain, deny, or audit mode)
 * Directory containing AppArmor profiles - These may be empty, but the profile names must match those in the logs (so if you rename a profile after gathering the logs, things might not update properly)

Once run, the logs and profiles are parsed, then the profiles are re-generated and output at the specified directory. The specified directory doesn't necessarily need to be the same path that is passed in as input and they can be different. The tool allows for mutation of profiles and output logs prior to regeneration, where needed, and has functionality for automatically replacing certain patterns with wildcards.

Additionally, some beta diffing functionality is provided that outputs changes made during profile generation.

Profile file names follow a standard pattern: the full path with dots (.) replacing slashes (/), for example: /bin/ls would be bin.ls.

# Usage
Requires Python 3+ 

```
usage: parse.py [-h] [--profile_dir PROFILE_DIR] [--log_file LOG_FILE] [--display] [--write WRITE] [--create CREATE]

optional arguments:
  -h, --help                show this help message and exit
  --profile_dir PROFILE_DIR
                            Directory containing current profiles
  --log_file LOG_FILE       Single log file for parsing
  --display                 Prints generated files
  --write WRITE             Writes generated profiles to <dst>
  --create CREATE           Write a profile for <proc path>
  --skip_profiles <list>    Comma separated list of profile filenames in profile_dir to skip parsing (e.g. profila,profileb,profilec)
  ```

