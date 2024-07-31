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

import argparse
import urllib.parse
import json
import requests
import boto3

def main():
    parser = argparse.ArgumentParser(description='Construct a URL that gives federated users direct access to the AWS Management Console')
    parser.add_argument('--profile', help='Use a specific profile from your credential file. If not given, then the default profile is used.')
    parser.add_argument('--role-name', required=True, help='IAM role to assume.')
    parser.add_argument('--account-id', required=True, help='AWS Account ID in which the role is located.')
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    sts_client = session.client('sts')

    # Assume AWS IAM Role
    response = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{args.account_id}:role/{args.role_name}',
        RoleSessionName='FederatedURLGenerator',
        DurationSeconds=3600
    )

    # Format temporary credentials into JSON
    session_string = {
        'sessionId': response['Credentials']['AccessKeyId'],
        'sessionKey': response['Credentials']['SecretAccessKey'],
        'sessionToken': response['Credentials']['SessionToken']
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
