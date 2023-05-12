'''
    Import URLError, HTTPError for Exception handling
    Import urlopen to handle url opening
    Import json module for parsing json data
'''
from urllib.error import URLError, HTTPError
from urllib.request import urlopen
import json

def _get_country_code_from_ip(_ip):
    '''Get Country code from ip using json response from ipinfo.io/json endpoint'''  
    try:
        _url = f'http://ipinfo.io/{_ip}/json'
        response = urlopen(_url, None)
        data = json.load(response)
        if 'country' in data:
            country_code = data['country']
        else:
            country_code = 'XX'
        return country_code
    except HTTPError as error_message:
        print(f"HTTP error: {error_message.code}")
        return 'XX'
    except URLError as error_message:
        print(f"URL error: {error_message.reason}")
        return 'XX'
