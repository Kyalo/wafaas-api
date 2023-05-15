#!/usr/bin/env python3
'''
"""
This code extracts rule IDs and other information from ModSecurity rule files.

First opens the rule files and reads them into memory. It then iterates over the lines in
each file, and for each line, it does the following:

* If the line is a comment, it is ignored.
* If the line starts with "SecRule", it marks the beginning of a new rule.
* If the line contains an ID, it extracts the ID and stores it in a dictionary.
* If the line contains a tag, it extracts the tag and stores it in the dictionary.
* If the line contains a "chain," it marks the end of the current rule.

while excluding certain rules based on their rule IDs.
Once all of the lines have been processed, the code writes the extracted information
to a new file.
'''

"""
import the glob module to easily find files that match a specified pattern
import the re module to use regular expressions
"""

import glob
import re

EXTRA_RULE_FILE = "RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf" # set a constant variable for the file name of the new rule file to be generated
SEPARATOR       = "MODSECPARSERSEPARATOR"   # set a constant variable for a separator string
END_OF_RULE     = "MODSECENDOFRULE" # set a constant variable for an end-of-rule string


RULES_PATH = "/etc/apache2/modsecurity-crs/coreruleset/rules/"  # set a variable for the directory where the ModSecurity rule files are located
requestfiles   = glob.glob(RULES_PATH + "/REQUEST-*.conf")  # use glob to find all files in the directory that start with "REQUEST-" and end with ".conf" and store them in a list
responsefiles  = glob.glob(RULES_PATH + "/RESPONSE-*.conf") # use glob to find all files in the directory that start with "RESPONSE-" and end with ".conf" and store them in a list
allfiles = requestfiles + responsefiles # combine the two lists of files

# create a dictionary of rule IDs to exclude
EXCLUDED_RULE_IDS = {
    "901340": 1,
    "920350": 1, # protocol enforcement
}


def _extract_and_place_in_dict(line, key, line_data):
    """
    Extracts the data for the given key from the given line and puts it into the line_data dictionary.
    Args:
        line: The string to search for key and data.
        key: The string key to search for.
        line_data: The dictionary to put the extracted key and data into.
    """
    regex = f".*{key}:'(.*)'"
    m = re.search(regex, line)
    if (m is not None):
        grabbed_data = m.groups()
        line_data[key] = grabbed_data[0]
        return

    regex = f".*{key}:(.*),"
    m = re.search(regex, line)
    if (m is not None):
        grabbed_data = m.groups()
        line_data[key] = grabbed_data[0]


def _clean_key_data(key_data):
    """
    Cleans up the key data by replacing certain characters with more parsable characters.
    Args:
        key_data: The string to clean up.
    Returns:
        The cleaned up string.
    """
    return key_data.replace("\\\"","").replace(",","-").replace("'",'').replace('"','').replace(" ","EMPTYSPACE")

# initialize an empty dictionary to store the unique IDs of the SecRule blocks that are found
rule_ids = {}

# Iterate over the rule files.
for rule_file in allfiles:
    # Skip files that have these strings in their file names
    if ('EXCLUSION' in rule_file or 'CORRELATION' in rule_file or 'BLOCKING-EVALUATION' in rule_file):
        # skip the current iteration of the loop and move to the next file if any of the above strings are found in the file name
        continue
    print("Looking at file {rule_file}")
    
    # Open the rule file for reading.
    with open(rule_file, "r") as in_file:
        buf = in_file.readlines()

    # Open the same file for writing (this will overwrite the contents of the file)
    with open(rule_file, "w") as out_file:
        inside_secrule = 0  # Set a variable to keep track of whether we are inside a SecRule block or not
        is_chain_rule = 0   # Set a variable to keep track of whether the SecRule block is a chained rule or not
        inside_chain_rule = 0   # Set a variable to keep track of whether we are inside a chained SecRule block or not
        
        line_data  = {} # Dictionary to store the data extracted from each line in the SecRule block
        file_lines = [] # List to store the lines that will be written to the output file
        rule_name  = "" # Store the name of the SecRule block

        # Iterate over the lines in the rule file.
        for line in buf:

            # Check for comment
            if (line.startswith("#")):
                file_lines.append(line)
                continue

            # If the line starts with "SecRule", it marks the beginning of a new rule.
            if ('SecRule' in line and not 'PARANOIA_LEVEL' in line):
                # If we are already inside a chained SecRule block, set 'inside_chain_rule' to True
                if (is_chain_rule):
                    inside_chain_rule = 1
                else:
                    print("--- Now inside secrule ---")
                    # Set 'inside_secrule' to True to indicate that we are now inside a SecRule block
                    inside_secrule = 1
                    # extract the name of the SecRule block from the line and store it in 'rule_name'
                    rule_name = line.split(" ")[1]

            # If we are inside a SecRule block, we extract the ID and tag from the line.
            if (inside_secrule):

                # Extract the ID.
                regex = ".*id:(\d+).*"
                m = re.search(regex, line)
                if (m is not None):
                    grabbed_data = m.groups()   # extract the data matched by the regular expression
                    rule_id = grabbed_data[0]   # store the ID in 'rule_id'
                    line_data['rule_id'] = rule_id  # add the ID to the 'line_data' dictionary
                    rule_ids[rule_id] = 1

                # Extract the tag.
                regex = ".*tag:'(.*),'"
                m = re.search(regex, line)
                if (m is not None):
                    grabbed_data = m.groups()
                    if ('tag' not in line_data):
                        line_data['tag'] = []
                    line_data['tag'].append(grabbed_data[0])

                # Extract the other information from the line.
                keys_to_extract = ['ver', 'phase', 'msg', 'logdata', 'severity']
                for key in keys_to_extract:
                    _extract_and_place_in_dict(line, key, line_data)

                # If the line contains "chain," it marks the end of the current rule.
                if 'chain,' in line:
                    is_chain_rule = 1

            # If the line is a newline, a blank line, or a comment, we ignore it
            if (line == '\n' or line == "" or line.isspace()):
                if (inside_secrule):
                    append_line = ""
                    if (len(line_data) > 2): #validation check
                        for key in line_data:
                            if type(line_data[key]) is list:
                                key_data = ",".join(line_data[key])
                            else:
                                key_data = line_data[key]

                            if (append_line == ""):
                                append_line += "setvar:TX." + line_data['rule_id']
                                append_line += f"={SEPARATOR}matched_var_names{SEPARATOR}%{{MATCHED_VARS_NAMES}}{SEPARATOR}matched_var_names{SEPARATOR}"
                                append_line += f"{SEPARATOR}matched_vars{SEPARATOR}" + "%{MATCHED_VARS}" + "{SEPARATOR}matched_vars{SEPARATOR}"
                                append_line += f"{SEPARATOR}rule_file{SEPARATOR}{rule_file}{SEPARATOR}rule_file{SEPARATOR}"
                                append_line += f"{END_OF_RULE}"

                            clean_key_data = _clean_key_data(key_data)
                            append_line += f"{SEPARATOR}{key}{SEPARATOR}{clean_key_data}{SEPARATOR}{key}{SEPARATOR}"

                        append_line += "\""
                        if ("FILES_TMP_CONTENT" not in rule_name and line_data['rule_id'] not in EXCLUDED_RULE_IDS):
                            tmp_line = file_lines[-1].rstrip()[:-1] + ",\\\n"
                            file_lines[-1] = tmp_line #adding to previous line
                            file_lines.append(append_line)

                    inside_secrule    = 0
                    is_chain_rule     = 0
                    inside_chain_rule = 0
                    line_data = {} #clean up the data grabbed

            print(line.strip())
            file_lines.append(line)

        for line in file_lines:
            out_file.write(line)

with open(f"{RULES_PATH}/{EXTRA_RULE_FILE}", "w") as out_file:
    line_to_write = 'SecRule REMOTE_ADDR "@unconditionalMatch" "phase:4,id:999434,prepend:'
    for rule_id in rule_ids:
        line_to_write += "%{TX." + rule_id + "}"
    line_to_write += '"'
    out_file.write(line_to_write)