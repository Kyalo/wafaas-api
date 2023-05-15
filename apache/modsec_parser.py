#!/usr/bin/env python3
'''
The code below reads ModSecurity rule files in a given directory, extracts 
specific data from them and generates a new rule file, while excluding 
certain rules based on their rule IDs.

import the glob module to easily find files that match a specified pattern
import the re module to use regular expressions
'''

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


rule_ids = {}
for rule_file in allfiles:
    # skip files that have these strings in their file names
    if ('EXCLUSION' in rule_file or 'CORRELATION' in rule_file or 'BLOCKING-EVALUATION' in rule_file):
        continue
    print("Looking at file {rule_file}")
    
    with open(rule_file, "r") as in_file:
        buf = in_file.readlines()

    with open(rule_file, "w") as out_file:  # open the same file for writing (this will overwrite the contents of the file)
        inside_secrule    = 0   # set a variable to keep track of whether we are inside a SecRule block or not
        is_chain_rule     = 0   # set a variable to keep track of whether the SecRule block is a chained rule or not
        inside_chain_rule = 0
        line_data  = {}
        file_lines = []
        rule_name  = ""
        for line in buf:
            #check for comment
            #print "Looking at line %s" % line
            if (line.startswith("#")):
                file_lines.append(line)
                continue

            if ('SecRule' in line and not 'PARANOIA_LEVEL' in line):
                if (is_chain_rule):
                    inside_chain_rule = 1
                else:
                    print("--- Now inside secrule ---")
                    inside_secrule = 1
                    rule_name = line.split(" ")[1]

            if (inside_secrule):
                regex = ".*id:(\d+).*"
                m = re.search(regex, line)
                if (m is not None):
                    grabbed_data = m.groups()
                    rule_id = grabbed_data[0]
                    line_data['rule_id'] = rule_id
                    rule_ids[rule_id] = 1

                regex = ".*tag:'(.*),'"
                m = re.search(regex, line)
                if (m is not None):
                    grabbed_data = m.groups()
                    if ('tag' not in line_data):
                        line_data['tag'] = []
                    line_data['tag'].append(grabbed_data[0])

                keys_to_extract = ['ver', 'phase', 'msg', 'logdata', 'severity']
                for key in keys_to_extract:
                    _extract_and_place_in_dict(line, key, line_data)

                if 'chain,' in line:
                    is_chain_rule = 1

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