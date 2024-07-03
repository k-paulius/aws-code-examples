"""
Generates example S3 HTTP Post request
https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-post-example.html
"""

import os
import sys
import datetime
import base64
import argparse
from sigv4_sign import get_signature, print_heading


def main(bucket, region):
    # Read AWS access key from env variables
    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key is None or secret_key is None:
        print('No access key is available.')
        sys.exit()

    # Create a date for headers and the credential string
    t = datetime.datetime.utcnow()
    amz_date   = t.strftime('%Y%m%dT%H%M%SZ')             # format: 20200515T172548Z
    exp_t      = t + datetime.timedelta(hours=1)          # expiration = 1h
    exp_date   = exp_t.strftime('%Y-%m-%dT%H:%M:%S.000Z') # format: 2015-12-30T12:00:00.000Z
    date_stamp = t.strftime('%Y%m%d')                     # format: 20200515

    service    = 's3'
    endpoint   = f"https://{bucket}.{service}.amazonaws.com"
    amz_cred   = access_key + '/' + date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    #acl        = 'public-read'
    acl        = 'private'

    post_policy = f"""{{ "expiration": "{exp_date}",
    "conditions": [
        {{"bucket": "{bucket}"}},
        ["starts-with", "$key", "user1/"],
        {{"acl": "{acl}"}},
        {{"success_action_redirect": "{endpoint}/successful_upload.html"}},
        ["starts-with", "$Content-Type", "image/"],
        {{"x-amz-meta-uuid": "14365123651274"}},
        {{"x-amz-server-side-encryption": "AES256"}},
        ["starts-with", "$x-amz-meta-tag", ""],
        {{"x-amz-credential": "{amz_cred}"}},
        {{"x-amz-algorithm": "AWS4-HMAC-SHA256"}},
        {{"x-amz-date": "{amz_date}" }}
    ]
}}"""

    post_policy_b64 = base64.b64encode(post_policy.encode('utf-8')).decode('utf-8')
    # Base64 encoded POST policy is the StringToSign
    signature = get_signature(secret_key, date_stamp, region, service, post_policy_b64)
    html_form = f"""<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  </head>
  <body>
    <form action="{endpoint}/" method="post" enctype="multipart/form-data">
    Key to upload:
    <input type="input"  name="key" value="user1/${{filename}}" /><br />
    <input type="hidden" name="acl" value="{acl}" />
    <input type="hidden" name="success_action_redirect" value="{endpoint}/successful_upload.html" />
    Content-Type:
    <input type="input"  name="Content-Type" value="image/jpeg" /><br />
    <input type="hidden" name="x-amz-meta-uuid" value="14365123651274" />
    <input type="hidden" name="x-amz-server-side-encryption" value="AES256" />
    <input type="text"   name="X-Amz-Credential" value="{amz_cred}" />
    <input type="text"   name="X-Amz-Algorithm" value="AWS4-HMAC-SHA256" />
    <input type="text"   name="X-Amz-Date" value="{amz_date}" />
    Tags for File:
    <input type="input"  name="x-amz-meta-tag" value="" /><br />
    <input type="hidden" name="Policy" value='{post_policy_b64}' />
    <input type="hidden" name="X-Amz-Signature" value="{signature}" />
    File:
    <!-- file field must be last field in the form -->
    <input type="file"   name="file" /> <br />
    <!-- The elements after this will be ignored -->
    <input type="submit" name="submit" value="Upload to Amazon S3" />
  </form>
</html>"""

    print_heading("Post Policy")
    print(post_policy)
    print_heading("Base64 post policy (string to sign)")
    print(post_policy_b64)
    print_heading("signature")
    print(signature)
    print_heading("HTML form")
    print(html_form)
    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bucket", required=True)
    parser.add_argument("-r", "--region", required=True)
    args = parser.parse_args()
    main(args.bucket, args.region)
