#!/usr/bin/env python3

# Copyright (c) 2024 k-paulius
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import argparse
import urllib.parse
import json
import requests
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


def parse_args():
    parser = argparse.ArgumentParser(description='Construct a URL that gives federated users direct access to the AWS Management Console')

    chain = parser.add_argument_group('Credential Provider Chain')
    chain.add_argument('--profile', help='Use a specific profile from your credential file. If not given, then the default profile is used.')
    chain.add_argument('--role-name', help='IAM role to assume.')
    chain.add_argument('--account-id', help='AWS Account ID in which the role is located.')

    static = parser.add_argument_group('Static Credentials')
    static.add_argument('--session-id', help='Access Key ID')
    static.add_argument('--session-key', help='Secret Access Key')
    static.add_argument('--session-token', help='Session Token')
    args = parser.parse_args()

    if not (
        (args.role_name and args.account_id) or
        (args.session_id and args.session_key and args.session_token)
    ):
        print("ERROR: You must provide either --role-name and --account-id or --session-id, --session-key, and --session-token")
        sys.exit()
    return args


def main():
    args = parse_args()

    if args.session_id:
        session_id = args.session_id
        session_key = args.session_key
        session_token = args.session_token
    else:
        try:
            session = boto3.Session(profile_name=args.profile)
            sts_client = session.client('sts')

            # Assume AWS IAM Role
            response = sts_client.assume_role(
                RoleArn=f'arn:aws:iam::{args.account_id}:role/{args.role_name}',
                RoleSessionName='FederatedURLGenerator',
                DurationSeconds=3600
            )
        except (ClientError, NoCredentialsError, ProfileNotFound) as e:
            print(f"ERROR: {e}")
            sys.exit()

        session_id = response['Credentials']['AccessKeyId']
        session_key = response['Credentials']['SecretAccessKey']
        session_token = response['Credentials']['SessionToken']

    # Format temporary credentials into JSON
    session_string = {
        'sessionId': session_id,
        'sessionKey': session_key,
        'sessionToken': session_token
    }

    # Call the AWS federation endpoint and supply the temporary security credentials to request a sign-in token
    req_params = {
        'Action': 'getSigninToken',
        'SessionDuration': 1800,
        'Session': json.dumps(session_string)
    }
    # GET or POST can be used to retrieve Sign-In token
    #response = requests.get("https://signin.aws.amazon.com/federation", req_params)
    response = requests.post("https://signin.aws.amazon.com/federation", req_params)
    signin_token = response.json()['SigninToken']

    # Build federated Sing-In URL
    req_params = {
        'Action': 'login',
        'Issuer': 'example.org',
        'Destination': 'https://console.aws.amazon.com/',
        'SigninToken': signin_token
    }
    signin_url = f"https://signin.aws.amazon.com/federation?{urllib.parse.urlencode(req_params)}"
    print(f"Sign-In URL:\n{signin_url}")

if __name__ == '__main__':
    main()
