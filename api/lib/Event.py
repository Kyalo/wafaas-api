"""
These modules provide utility functions for working with UUIDs, JSON, logging, and datetime.

Module level functions:
- uuid.uuid4(): generate a random UUID
- json.dumps(obj): serialize obj to a JSON formatted string
- logging.getLogger(name): get a logger instance
- datetime.datetime.now(tz): get the current date and time

from google.cloud import pubsub_v1: This module provides utility functions for working with
    Pub/Sub messaging in the Google Cloud environment.

Module level functions:
- pubsub_v1.PublisherClient(): get a client object for publishing messages to a Pub/Sub topic
- pubsub_v1.SubscriberClient(): get a client object for subscribing to a Pub/Sub topic
- pubsub_v1.types.PubsubMessage(data=message_data_bytes): create a PubsubMessage with the 
    specified message data
- pubsub_v1.enums.BatchSettings(max_messages=batch_size): configure batching settings for 
    messages sent to a Pub/Sub topic

"""
import uuid
import json
import logging
import datetime
from google.cloud import pubsub_v1

"""
import custom modules for encryption and retrieving country code from ip
""" 
from Encryption_decryption import encrypt_data
from Get_code_from_ip import _get_country_code_from_ip

TOPIC_NAME = "raw_events"

publisher  = pubsub_v1.PublisherClient()


def _get_request_headers(request):
    headers = {}
    for key in request.headers.keys():
        headers[key] = request.headers.get(key)
    return headers

### EVENT ###

def callback(message_future):
    """
    Handle the result of a Pub/Sub message publication.

    Args:
        message_future (google.api_core.future.Future): A Future instance representing the
            result of the message publication.

    Returns:
        None

    Raises:
        logging.error: If there is an exception raised during message publication.

    """
    if message_future.exception():
        logging.error('Publishing message threw an Exception %s.', message_future.exception())
    else:
        logging.debug('Message created: %s.', message_future.result())


def create_event(request):
    """Creates an event dictionary based on the given request.
    
    Args:
        request: The Flask request object.
    
    Returns:
        A dictionary containing the following fields:
        - UUID: A unique identifier for the event (string)
        - created: The ISO-formatted timestamp for when the event was created (string)
        - created_epoch: The epoch timestamp for when the event was created (string)
        - scheme: The URL scheme used in the request (string)
        - full_path: The full path of the requested resource (string)
        - method: The HTTP method used in the request (string)
        - url: The full URL of the requested resource (string)
        - data: The encrypted request data (string)
        - headers: A dictionary of request headers (dict)
        - endpoint: The name of the Flask endpoint that handled the request, or 'MISSING'
            if not found (string)
        - user-agent: The User-Agent string from the request headers (string)
        - ip: The IP address of the client that made the request (string)
        - geo.src: The ISO 3166-1 alpha-2 country code of the client's IP address, if known (string)
    """
    event = {}
    event["UUID"]          = str(uuid.uuid4())
    event["created"]       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event["created_epoch"] = datetime.datetime.now().strftime("%s")
    event["scheme"]        = request.scheme
    event["full_path"]     = request.full_path
    event["method"]        = request.method
    event["url"]           = request.url
    event["data"]          = encrypt_data(json.dumps(request.form))
    # event["data"]          = json.dumps(request.form)
    event["headers"]       = _get_request_headers(request)

    if request.endpoint is not None:
        event["endpoint"] = request.endpoint
    else:
        event["endpoint"] = 'MISSING'

    # extra tags
    event["user-agent"] = request.user_agent.string
    event["ip"]         = request.remote_addr
    event["geo.src"]    = _get_country_code_from_ip(request.remote_addr)

    return event

def send_event(event, project_name):
    """
    Publishes an event to a Google Cloud Pub/Sub topic.

    Args:
        event: A dictionary representing the event to be published. This dictionary can contain
            strings, dictionaries, and lists.
        project_name: A string representing the name of the Google Cloud project containing
            the Pub/Sub topic to publish the event to. 

    Returns: 
        None

    Raises:
        Any exceptions raised by the `publisher.publish()` function.
    """
    for key in event:
        if isinstance(event[key], (dict, list)):
            event[key] = json.dumps(event[key])
    json_event = json.dumps(str(event))

    data = f'{json_event}'
    data = data.encode('utf-8')
    message_future = publisher.publish(publisher.topic_path(project_name, TOPIC_NAME), data=data)
    message_future.add_done_callback(callback)
    logging.info("Sending event: %s", json_event)
