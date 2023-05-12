#!/usr/bin/env python3

import time
import glob
import re

EXTRA_RULE_FILE = "RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
SEPARATOR       = "MODSECPARSERSEPARATOR"
END_OF_RULE     = "MODSECENDOFRULE"

RULES_PATH = "/etc/apache2/modsecurity-crs/coreruleset/rules/"
requestfiles   = glob.glob(RULES_PATH + "/REQUEST-*.conf")
responsefiles  = glob.glob(RULES_PATH + "/RESPONSE-*.conf")
allfiles = requestfiles + responsefiles

EXCLUDED_RULE_IDS = {
    "901340": 1,
    "920350": 1, # protocol enforcement
}


def _extract_and_place_in_dict(line, key, line_data):
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
    return key_data.replace("\\\"","").replace(",","-").replace("'",'').replace('"','').replace(" ","EMPTYSPACE")


rule_ids = {}
for rule_file in allfiles:
    if ('EXCLUSION' in rule_file or 'CORRELATION' in rule_file or 'BLOCKING-EVALUATION' in rule_file):
        continue
    print("Looking at file {rule_file}")
    
    with open(rule_file, "r") as in_file:
        buf = in_file.readlines()

    with open(rule_file, "w") as out_file:
        inside_secrule    = 0
        is_chain_rule     = 0
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
                                append_line += "=%smatched_var_names%s" % (SEPARATOR, SEPARATOR) + "%{MATCHED_VARS_NAMES}" + "%smatched_var_names%s" % (SEPARATOR, SEPARATOR)
                                append_line += f"{SEPARATOR}matched_vars{SEPARATOR}" + "%{MATCHED_VARS}" + "{SEPARATOR}matched_vars{SEPARATOR}"
                                append_line += f"{SEPARATOR}rule_file{SEPARATOR}{rule_file}{SEPARATOR}rule_file{SEPARATOR}"
                                append_line += f"{END_OF_RULE}"

                            clean_key_data = _clean_key_data(key_data)
                            # append_line += "%s%s%s%s%s%s%s" % (SEPARATOR, key, SEPARATOR,clean_key_data,SEPARATOR,key,SEPARATOR)
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

with open("%s/%s" % (RULES_PATH,EXTRA_RULE_FILE), "w") as out_file:
    line_to_write = 'SecRule REMOTE_ADDR "@unconditionalMatch" "phase:4,id:999434,prepend:'
    for rule_id in rule_ids:
        line_to_write += "%{TX." + rule_id + "}"
    line_to_write += '"'
    out_file.write(line_to_write)