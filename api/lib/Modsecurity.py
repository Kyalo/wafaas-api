'''
Import logging module for logging purposes
Import requests module for making HTTP requests
Import urlparse and urljoin for URL parsing
Import Path for working with file paths
'''
import logging
import requests
from urllib.parse import urlparse, urljoin
from pathlib import Path

MOSEC_SEPARATOR = "MODSECPARSERSEPARATOR"   # Set a constant string to be used as a separator in the MODSEC response
MODSEC_URL      = "http://localhost"    # Set the URL of the MODSEC server


def _convert_keys_to_string(headers):
    """
    Convert keys in a dictionary to strings.

    Args:
        headers (dict): The dictionary of headers whose keys should be converted to strings.

    Returns:
        dict: A new dictionary with string keys.
    """
    new_dict = {}
    for header in headers:
        new_dict[str(header)] = str(headers[header])
    return new_dict


def _to_chunks(l, n):
    """
    Splits a list into smaller sub-lists of a fixed size.

    Args:
        l (list): The list to be split into chunks.
        n (int): The maximum number of elements that should be contained in each chunk.

    Returns:
        A generator that produces sub-lists of the specified size.
    """
    n = max(1, n)
    return (l[i:i+n] for i in range(0, len(l), n))


def _parse_modsec_response(modsec_content):
    """
    Parses the response from the ModSecurity module and extracts any alerts that it finds.

    Args:
        modsec_content (str): The content of the response from the ModSecurity module.

    Returns:
        List[Dict[str, Union[str, List[str]]]]: A list of alerts. Each alert is represented as a dictionary
        with the following keys:
            - matched_var_names: A string containing the names of the variables that matched the rule.
            - rule_id: A string containing the ID of the rule that was triggered.
            - rule_message: A string containing the message of the rule that was triggered.
            - tags: A list of strings containing the tags associated with the rule that was triggered.
    """

    results = modsec_content.replace("EMPTYSPACE"," ").split(MOSEC_SEPARATOR)
    result_list = list(_to_chunks(results, 4))[:-1]
    logging.debug(result_list)

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
    """
    Sends an HTTP request to the ModSecurity firewall and returns whether
    the request is considered an attack or not, as well as a list of any
    detected alerts.

    Args:
        request_data: A dictionary containing information about the HTTP
            request to send. Must have the following keys:
            - "method": The HTTP method of the request (string).
            - "path": The path of the request URL (string).
            - "data": The request data (string).
            - "headers": A dictionary of request headers.
            - "content": Optional request content to send in the
                "X-CONTENT-FIELD-WAF" header (string).

    Returns:
        A dictionary with two keys:
        - "is_attack": A boolean indicating whether the request is
            considered an attack or not.
        - "alerts": A list of dictionaries, where each dictionary
            represents an alert detected by the ModSecurity firewall.
            Each dictionary has the following keys:
            - "matched_var_names": A string indicating the name of the
                variable(s) that matched the rule.
            - Other keys indicating the properties of the alert, such as
                "severity", "id", "msg", etc.
    """

    method = request_data['method']
    path = request_data['path']
    data = request_data['data']

    headers = _convert_keys_to_string(request_data['headers'])

    if 'content' in request_data:
        headers['X-CONTENT-FIELD-WAF'] = request_data['content']
        logging.info("Sending in X-CONTENT-FIELD-WAF => %s", request_data['content'])

    # fix path if necessary
    if (not path.startswith("/")):
        path = f"/{path}"

    modsec_url_request = f"{MODSEC_URL}{path}"

    parsed_url = urlparse(modsec_url_request)
    path       = Path(parsed_url.path).absolute()
    query      = parsed_url.query

    complete_url = f"{MODSEC_URL}{path}"
    if (len(query) > 0):
        complete_url = f"{complete_url}?{query}"

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
    logging.debug(r.content)

    result = {}
    if (len(alerts)):
        result = { "is_attack": 1 , "alerts": alerts }
    else:
        result = { "is_attack": 0 }

    return result

