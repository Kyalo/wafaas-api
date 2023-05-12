import logging
import requests
from urlparse import urlparse, urljoin
from unipath import Path
import json

MOSEC_SEPARATOR = "MODSECPARSERSEPARATOR"
MODSEC_URL      = "http://localhost"

def _convert_keys_to_string(headers):
    new_dict = {}
    for header in headers:
        new_dict[str(header)] = str(headers[header])
    return new_dict

def _to_chunks(l, n):
    n = max(1, n)
    return (l[i:i+n] for i in xrange(0, len(l), n))

def _parse_modsec_response(modsec_content):
    results = modsec_content.replace("EMPTYSPACE"," ").split(MOSEC_SEPARATOR)
    result_list = list(_to_chunks(results, 4))[:-1]
    #logging.debug(result_list)

    alerts = []
    tmp_alert = {}
    for result in result_list:
        key_name = result[1]
        value    = result[2]
        if (key_name == 'matched_var_names'):
            #flush if there is anything
            if (key_name in tmp_alert):
                alerts.append(tmp_alert)
            tmp_alert = {}
            tmp_alert[key_name] = value
        else:
            tmp_alert[key_name] = value

    if (len(tmp_alert)):
        alerts.append(tmp_alert)
    return alerts

def review_modsec(request_data):

    method = request_data['method']
    path = request_data['path']
    data = request_data['data']

    headers = _convert_keys_to_string(request_data['headers'])

    if 'content' in request_data:
        headers['X-CONTENT-FIELD-WAF'] = request_data['content']
        #logging.info("Sending in X-CONTENT-FIELD-WAF => %s" % request_data['content'])

    # fix path if necessary
    if (not path.startswith("/")):
        path = "/%s" % path

    modsec_url_request = "%s%s" % (MODSEC_URL, path)

    parsed_url = urlparse(modsec_url_request)
    path       = Path(parsed_url.path).absolute()
    query      = parsed_url.query

    complete_url = "%s%s" % (MODSEC_URL, path)
    if (len(query) > 0):
        complete_url = "%s?%s" % (complete_url, query)

    if (method == "GET"):
        if (len(headers) > 0):
            r = requests.get(complete_url, headers=headers)
            logging.info("Performing GET request with headers")
        else:
            r = requests.get(complete_url)
            logging.info("Performing GET request without headers")
    elif (method == "POST"):
        if (len(headers) > 0):
            r = requests.post(complete_url, data = data, headers = headers)
            logging.info("Performing POST request with headers")
        else:
            r = requests.post(complete_url, data = data)
            logging.info("Performing POST request without headers")

    alerts = _parse_modsec_response(r.content)
    #logging.debug(r.content)

    result = {}
    if (len(alerts)):
        result = { "is_attack": 1 , "alerts": alerts }
    else:
        result = { "is_attack": 0 }

    return result