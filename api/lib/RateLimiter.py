import redis
import logging
import datetime

ALLOWED_EVENT_IDENTIFIERS = ["ip", "user-agent", "login_id"]
RATE_LIMIT_MAX            = 1000

def review_rate_limiter(request_data):
	r = redis.StrictRedis(host='redis', port=6379, db=0)
	print(r)
	event = request_data['event']
	for identifier in ALLOWED_EVENT_IDENTIFIERS:
		if identifier in event:
			identifier_value = event[identifier]
			
			now_epoch    = int(datetime.datetime.now().strftime("%s"))
			minute_epoch = now_epoch - (now_epoch % 60)
			rate_limiting_key = f"waf_rate_limiter#{identifier.lower()}#{identifier_value.lower()}#{minute_epoch}"
			logging.info("[RateLimiter] Checking for redis key: %s", rate_limiting_key)
			increment = r.incr(rate_limiting_key, 1)
			r.expire(rate_limiting_key, 60)

			if (increment > RATE_LIMIT_MAX):
				return {"is_attack": 1, "identifier": identifier, "identifier_value": identifier_value, "rate_limit_value": increment}				

	return {"is_attack": 0}