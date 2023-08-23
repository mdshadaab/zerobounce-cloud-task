import os
from elasticsearch import Elasticsearch
import json
from datetime import datetime
from dotenv import load_dotenv
import traceback
import logging
import http
import tldextract

load_dotenv()

ELASTIC_CLOUD_ID = os.getenv("ELASTIC_CLOUD_ID")
ELASTIC_USER = os.getenv('ELASTIC_USER')
ELASTIC_PASSWORD = os.getenv('ELASTIC_PASSWORD')
ZEROBOUNCE_KEY = os.getenv('ZEROBOUNCE_KEY')

es = Elasticsearch(
    cloud_id= ELASTIC_CLOUD_ID,
    http_auth=(ELASTIC_USER, ELASTIC_PASSWORD)
)
def extract_domain(url):
    ext = tldextract.extract(url)
    domain = ext.registered_domain
    return domain

def bulk_verify_emails(unverified_emails: dict):
    """
    Verifies a batch of email addresses using the ZeroBounce email validation API.

    Args:
        unverified_emails (dict): A dictionary of email addresses to be verified. The keys are the email
            addresses and the values are unique identifiers for each email address.

    Returns:
        A dictionary with two keys:
        - "success": True if the API call was successful, False otherwise.
        - "data": A dictionary with verified email addresses as keys and a dictionary of email validation
            details as values. The email validation details include the email status (valid, invalid, catch-all),
            sub-status (e.g. "disposable", "role-based"), MX server URL, and whether the email is valid based
            on the MX server's catch-all policy.

    Raises:
        Exception: If the API call was unsuccessful, raises an exception with the error message returned by
            the API.
    """
    try:
        conn = http.client.HTTPSConnection("bulkapi.zerobounce.net")
        list_of_emails = []
        # list of mx servers for which catch-all email ids will be valid
        catch_all_domains = ['outlook.com', 'microsoft.com', 'office365.us']
        for email in unverified_emails:
            list_of_emails.append({
                "email_address": email
            })
        payload = {
            "api_key": ZEROBOUNCE_KEY,
            "email_batch": list_of_emails
        }
        payload = json.dumps(payload)

        headers = {
            'x-token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImhlbnJ5QHplcm9ib3VuY2UubmV0IiwiZXhwIjoxNTk1NzEzNTI1fQ.nzOT-bJ8_tvnrNy3t1DeIDNMXxS-YEvlCbZye-9vpr4',
            'Content-Type': 'application/json',
            'Cookie': '__cfduid=db977bdba3d06a8c9c19b45a92d6221b41572452483'
        }
        conn.request("POST", "/v2/validatebatch", payload, headers)
        res = conn.getresponse()
        data = res.read()
        data = json.loads(data.decode("utf-8"))
        verified_emails = {}
        for each in data['email_batch']:
            email_valid = ("false" if each["status"] != 'valid' else "true")
            if each["status"] == 'catch-all':
                domain = extract_domain(each['mx_record'])
                if domain in catch_all_domains:
                    email_valid = "true"
            verified_emails[each["address"]] = {
                '_id': unverified_emails[each["address"]],
                'email_status': each["status"],
                'email_sub_status': each["sub_status"],
                'mx_server_url': each['mx_record'],
                'email_valid': email_valid
            }
        if len(data['errors']) > 0:
            raise Exception(data['errors'])
        return {
            "success": True,
            "data": verified_emails
        }
    except:
        logging.exception(traceback.print_exc())
        

def es_update_email_data(checked_emails):
    """
    Updates email validation data for a batch of email addresses in Elasticsearch.

    Args:
        checked_emails (dict): A dictionary of verified email addresses and their validation details. The keys
            are the email addresses and the values are dictionaries with keys such as "email_valid", "email_status",
            "email_sub_status", "mx_server_url", etc.

    Returns:
        None

    Raises:
        Exception: If there is an error while updating the email data in Elasticsearch, raises an exception
            with the error message.
    """
    try:
        body = []
        for each in checked_emails:
            body.append(
                {
                    "update": {"_id": checked_emails[each]['_id'], "_index": "thetouch-ai-business-processed"}
                }
            )
            body.append({
                "doc": {
                    "email_valid": checked_emails[each]['email_valid'],
                    "email_status": checked_emails[each]['email_status'],
                    "email_sub_status": checked_emails[each]['email_sub_status'],
                    "mx_server_url": checked_emails[each]['mx_server_url'],
                    "last_verified": int(datetime.utcnow().timestamp() * 1000),
                    "updated_at": int(datetime.utcnow().timestamp() * 1000)
                },
                "doc_as_upsert": True,
            })
        es.bulk(body)
        

    except Exception as error:
        logging.exception(traceback.print_exc())
        

def verify_update_email_data(request):
    try:
        request_json = request.get_json()
        unverified_emails = request_json['unverified_emails']
        checked_emails = bulk_verify_emails(unverified_emails)
        if checked_emails['success']:
            es_update_email_data(checked_emails['data'])
        return "success"

    except Exception as error:
        logging.exception(traceback.print_exc())
        return "failed"


