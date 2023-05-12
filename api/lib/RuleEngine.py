import redis
import logging

ALLOWED_EVENT_IDENTIFIERS = ["ip", "user-agent", "login_id"]

def review_rule_engine(request_data):
	r = redis.StrictRedis(host='redis', port=6379, db=0)

	event = request_data['event']
	for identifier in ALLOWED_EVENT_IDENTIFIERS:
		if identifier in event:
			identifier_value = event[identifier]
			key = f"waf_block_rule#{identifier.lower()}#{identifier_value.lower()}"
			logging.info("[RuleEngine] Checking for redis key: %s", key)
			exists = r.get(key)
			if (exists != None):
				return {"is_attack": 1, "identifier": identifier, "identifier_value": identifier_value}

	return {"is_attack": 0}