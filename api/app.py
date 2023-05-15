from bottle import route, run, request
import requests
import pprint
import json
import traceback
import logging
import argparse

import lib.Modsecurity as Modsecurity
import lib.RuleEngine  as RuleEngine
import lib.RateLimiter as RateLimiter

parser = argparse.ArgumentParser(description='Port to use')
parser.add_argument('--port', type=int, default=8080, help='an integer for the accumulator')
args = parser.parse_args()
pp = pprint.PrettyPrinter(indent=4)

app = Flask(__name__)
app.config.from_object(Config)

@route('/ping', method='GET')
def ping():
    return "pong"

@route('/process_request', method='POST')
def process_request():
    logging.info("Received request")

    request_body = request.body.getvalue()
    #logging.debug("request body " + request_body)

    request_data = json.loads(str(request_body))
    logging.info(request_data)

    # VALIDATION
    mandatory_fields = ['method', 'path', 'headers', 'data', 'event']
    for field in mandatory_fields:
        if (field not in request_data):
            result = { "error": "Method missing for request: %s" % field}
            return result
        if (field == "method" and request_data['method'] not in ("GET", "POST")):
            result = { "error": "Method %s not allowed, only GET or POST are accepted" % request_data['method'] }
            return result

    # TODO MODIFY
    if (not isinstance(request_data['headers'], dict)):
        request_data['headers'] = json.loads(request_data['headers'])
    if (not isinstance(request_data['event'], dict)):
        request_data['event'] = json.loads(request_data['event'])

    logging.info("Processing request")
    result = {"status": "Normal"}

    # MODSECURITY
    modsec_response_data = Modsecurity.review_modsec(request_data)
    if (modsec_response_data['is_attack'] == 1):
        result['status'] = 'Attack'
        result['attack_source'] = "modsecurity"
    result['modsecurity'] = json.dumps(modsec_response_data)

    # RULE ENGINE
    rule_engine_data = RuleEngine.review_rule_engine(request_data)
    if (rule_engine_data['is_attack'] == 1):
        result['status'] = 'Attack'
        result['attack_source'] = "rule_engine"
    result['rule_engine'] = json.dumps(rule_engine_data)

    # RATE LIMITER
    rate_limiter_data = RateLimiter.review_rate_limiter(request_data)
    if (rate_limiter_data['is_attack'] == 1):
        result['status'] = 'Attack'
        result['attack_source'] = "rate_limiter"
    result['rate_limiter'] = json.dumps(rate_limiter_data)

    logging.info(result)
    return result

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run(host='0.0.0.0', port=args.port)

#DB2 SQL error

#curl -s localhost:8080/process_request -XPOST -d '{"method":"GET", "path":"../../../../etc/passwd?param=SELECT * FROM INFORMATION_SCHEMA&other=../../../../../etc/passwd", "headers":{}, "data":{}}'|jq

#lib.Event.encrypt_data("Exception details: com.mysql.jdbc.MysqlDataTruncation")
#curl -s localhost:8082/process_request -XPOST -d '{"method":"GET", "path":"../../../../etc/passwd?param=SELECT * FROM INFORMATION_SCHEMA&other=../../../../../etc/passwd", "headers":{"X_CONTENT_FIELD_WAF":"dg24/s0DwuzP55rbF/9BD8kjPNDBfbH9WSqToxxZI5atRQ5kxEbtkEQaG8XqYrHENjeztqOI2Jn1TeeaYlIkcmPWOKKHQSzCe9VOvLLfosY="}, "data":{}}'|jq

#curl -s localhost:8080/process_request -XPOST -d '{"method":"GET", "path":"", "headers":{}, "data":{}, "content":"0lez+ZI1aE1Vj8m9B28ZCegKDtI5//7cwY/IolMPQerCW3yxV+o+GWmLV5tLpSVE"}'|jq
