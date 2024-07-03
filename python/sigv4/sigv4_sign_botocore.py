import os
import sys
import argparse
import requests
import logging
from botocore.credentials import Credentials
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

# AWS auth types
AUTH_TYPE_GET_HEADER  = 'get-header'
AUTH_TYPE_POST_HEADER = 'post-header'


def main(auth_type):
    # Read AWS access key from env variables
    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key is None or secret_key is None:
        print('No access key is available.')
        sys.exit()

    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    service     = 'ec2'
    region      = 'us-east-1'
    endpoint    = 'https://ec2.amazonaws.com'

    if auth_type == AUTH_TYPE_GET_HEADER:
        http_method = 'GET'
        payload = ''
        headers = {}
        params  = {
            'Action': 'DescribeRegions',
            'RegionName.1': 'us-east-2',
            'Version': '2016-11-15'
        }
    elif auth_type == AUTH_TYPE_POST_HEADER:
        http_method = 'POST'
        payload = {
            'Action': 'DescribeRegions',
            'RegionName.1': 'us-east-2',
            'Version': '2016-11-15'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'
        }
        params  = {}

    credentials = Credentials(access_key, secret_key)
    sigv4 = SigV4Auth(credentials, service, region)
    request = AWSRequest(
        method=http_method,
        url=endpoint,
        data=payload,
        headers=headers,
        params=params
    )
    sigv4.add_auth(request)
    prepped_r = request.prepare()

    logger.debug(f"URL: {prepped_r.url}")
    logger.debug(f"Body: {prepped_r.body}")
    logger.debug(f"Headers: {prepped_r.headers}")
    logger.debug(f"Method: {prepped_r.method}")

    if auth_type == AUTH_TYPE_GET_HEADER:
        r = requests.get(prepped_r.url, headers=prepped_r.headers)
    elif auth_type == AUTH_TYPE_POST_HEADER:
        r = requests.post(prepped_r.url, data=prepped_r.body, headers=prepped_r.headers)

    logger.debug(f"Response code: {r.status_code}")
    logger.debug(r.text)

    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--auth-type", required=True, choices=[AUTH_TYPE_GET_HEADER, AUTH_TYPE_POST_HEADER])
    args = parser.parse_args()
    main(args.auth_type)
