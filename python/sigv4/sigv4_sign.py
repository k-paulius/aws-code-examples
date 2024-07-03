#
# Example code showcasing AWS Signature Version 4 generation
# based on examples from https://github.com/awsdocs/aws-doc-sdk-examples/tree/main/python/example_code/signv4
#
import sys, os, datetime, hashlib, hmac, urllib.parse
import requests
import argparse

# AWS auth types
AUTH_TYPE_GET_HEADER       = 'get-header'
AUTH_TYPE_GET_QUERY_STRING = 'get-query'
AUTH_TYPE_POST_HEADER      = 'post-header'

# examples
EXAMPLE_EC2_DESCRIBEREGIONS = "ec2-describeregions"
EXAMPLE_DDB_CREATETABLE     = "ddb-createtable"


# see: botocore.SigV4Auth._sign
# generates HMAC-SHA256 digest
def sign_message(key, msg, hex=False):
    sig = hmac.new(key, msg.encode('utf-8'), hashlib.sha256)

    if hex:
        sig = sig.hexdigest()
    else:
        sig = sig.digest()
    return sig


# generates signing key
def gen_signing_key(key, dateStamp, regionName, serviceName):
    kDate     = sign_message((f"AWS4{key}").encode('utf-8'), dateStamp)
    kRegion   = sign_message(kDate, regionName)
    kService  = sign_message(kRegion, serviceName)
    kSigning  = sign_message(kService, 'aws4_request')
    return kSigning


# see: botocore.SigV4Auth.signature
# calculates signature
def get_signature(key, dateStamp, regionName, serviceName, stringToSign):
    kSigning  = gen_signing_key(key, dateStamp, regionName, serviceName)
    signature = sign_message(kSigning, stringToSign, hex=True)
    return signature


def print_heading(heading):
    heading = f" [{heading}] "
    print(f"{heading:-^80}")
    return


def main(example, auth_type):
    # Read AWS access key from env variables
    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key is None or secret_key is None:
        print('No access key is available.')
        sys.exit()

    # Create a date for headers and the credential string
    t = datetime.datetime.utcnow()
    amz_date   = t.strftime('%Y%m%dT%H%M%SZ') # Format date as YYYYMMDD'T'HHMMSS'Z'
    date_stamp = t.strftime('%Y%m%d')         # Date w/o time, used in credential scope

    ############################################################
    # Example 1 - EC2:DescribeRegions
    ############################################################
    if example == EXAMPLE_EC2_DESCRIBEREGIONS:
        service   = 'ec2'
        host      = 'ec2.amazonaws.com'
        region    = 'us-east-1'
        endpoint  = 'https://ec2.amazonaws.com'

        algorithm        = 'AWS4-HMAC-SHA256'
        credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
        amz_target_header = None

        if auth_type == AUTH_TYPE_GET_HEADER:
            http_method           = 'GET'
            canonical_uri         = '/'
            content_type_header   = ''
            canonical_headers     = 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
            signed_headers        = 'host;x-amz-date'
            canonical_querystring = 'Action=DescribeRegions&RegionName.1=us-east-1&Version=2016-11-15'
            payload               = ''

        elif auth_type == AUTH_TYPE_GET_QUERY_STRING:
            http_method           =  'GET'
            canonical_uri         =  '/'
            content_type_header   =  ''
            canonical_headers     =  'host:' + host + '\n'
            signed_headers        =  'host'
            canonical_querystring =  'Action=DescribeRegions&RegionName.1=us-east-1&Version=2016-11-15'
            canonical_querystring += '&X-Amz-Algorithm=' + algorithm
            canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(access_key + '/' + credential_scope)
            canonical_querystring += '&X-Amz-Date=' + amz_date
            canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers
            payload               =  ''

        elif auth_type == AUTH_TYPE_POST_HEADER:
            http_method           = 'POST'
            canonical_uri         = '/'
            content_type_header   = 'application/x-www-form-urlencoded; charset=utf-8'
            canonical_headers     = 'content-type:' + content_type_header + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
            signed_headers        = 'content-type;host;x-amz-date'
            canonical_querystring = ''
            payload               = 'Action=DescribeRegions&RegionName.1=us-east-1&Version=2016-11-15'

    ############################################################
    # Example 2 - dynamodb:CreateTable
    ############################################################

    elif example == EXAMPLE_DDB_CREATETABLE:
        service   = 'dynamodb'
        host      = 'dynamodb.us-east-1.amazonaws.com'
        region    = 'us-east-1'
        endpoint  = 'https://dynamodb.us-east-1.amazonaws.com'

        algorithm        = 'AWS4-HMAC-SHA256'
        credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'

        if auth_type == AUTH_TYPE_POST_HEADER:
            http_method           = 'POST'
            canonical_uri         = '/'
            content_type_header   = 'application/x-amz-json-1.0'
            amz_target_header     = 'DynamoDB_20120810.CreateTable'
            canonical_headers     = 'content-type:' + content_type_header + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-target:' + amz_target_header + '\n'
            signed_headers        = 'content-type;host;x-amz-date;x-amz-target'
            canonical_querystring = ''
            payload =  '{'
            payload +=  '"KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],'
            payload +=  '"TableName": "TestTable","AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],'
            payload +=  '"ProvisionedThroughput": {"WriteCapacityUnits": 5,"ReadCapacityUnits": 5}'
            payload +=  '}'


    ############################################################
    # Step 1: Create a canonical request
    ############################################################

    # HTTP method
    http_method = http_method

    # Canonical URI
    #
    # URI-encoded version of the absolute path component URL (everything between the host and the question mark character (?) that starts the query string parameters)
    # If the absolute path is empty, use a forward slash character (/)
    canonical_uri = canonical_uri

    # Canonical Query String
    #
    # URL-encoded query string parameters, separated by &
    # Encode names and values separately. If there are empty parameters, append the equals sign to the parameter name before encoding.
    # After encoding, sort the parameters alphabetically by key name. If there is no query string, use an empty string.
    #
    # In this example (a GET request), request parameters are in the query string. For this example, the query string is pre-formatted in the request_parameters variable.
    canonical_querystring = canonical_querystring

    # Canonical Headers
    #
    # The request headers, that will be signed, and their values, separated by newline characters.
    # Header names must use lowercase characters, must appear in alphabetical order, and must be followed by a colon (:).
    # For the values, trim any leading or trailing spaces, convert sequential spaces to a single space, and separate the values for a multi-value header using commas.
    # You MUST include the `host` header (HTTP/1.1) and any `x-amz-*` headers in the signature.
    # You can optionally include other standard headers in the signature, such as `content-type`.
    canonical_headers = canonical_headers

    # Signed Headers
    #
    # The list of headers that you included in canonical_headers, separated by semicolons (;).
    # This indicates which headers are part of the signing process.
    # Header names must use lowercase characters and must appear in alphabetical order.
    signed_headers = signed_headers

    # Hashed Payload
    #
    # SHA-256 hash of the payload in the body of the HTTP request
    # This string uses lowercase hexadecimal characters.
    # If the payload is empty, use an empty string as the input to the hash function.
    payload_hash = hashlib.sha256((payload).encode('utf-8')).hexdigest()

    # Create a canonical request by concatenating the following strings, separated by newline characters
    canonical_request = http_method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    print_heading("payload")
    print(payload)
    print_heading("payload hash")
    print(payload_hash)
    print_heading("canonical request")
    print(canonical_request)

    ############################################################
    # Step 2: Create a hash of the canonical request
    ############################################################

    # SHA-256 hash of the canonical request
    canonical_req_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    print_heading("canonical request hash")
    print(canonical_req_hash)

    ############################################################
    # Step 3: Create a string to sign
    ############################################################

    # Algorithm
    #
    # The algorithm used to create the hash of the canonical request. For SHA-256, the algorithm is `AWS4-HMAC-SHA256`.
    algorithm = algorithm

    # Request Date Time
    #
    # The date and time used in the credential scope.
    request_date_time = amz_date

    # Credential Scope
    #
    # This restricts the resulting signature to the specified Region and service.
    # The string has the following format: `YYYYMMDD/region/service/aws4_request`.
    credential_scope = credential_scope

    # Create a string by concatenating the following strings, separated by newline characters.
    string_to_sign = algorithm + '\n' +  request_date_time + '\n' +  credential_scope + '\n' +  canonical_req_hash

    print_heading("string to sign")
    print(string_to_sign)

    ############################################################
    # Step 4: Calculate the signature
    ############################################################

    signature = get_signature(secret_key, date_stamp, region, service, string_to_sign)

    print_heading("signature")
    print(signature)

    ############################################################
    # Step 5: Add the signature to the request
    ############################################################

    # You can add authentication information to a request using either the HTTP `Authorization` header or query string parameters.

    if auth_type == AUTH_TYPE_GET_HEADER or auth_type == AUTH_TYPE_POST_HEADER:
        authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
        print_heading("authorization header")
        print(authorization_header)

        http_headers = {
            'X-Amz-Date':amz_date,
            'Authorization':authorization_header
        }
        if content_type_header:
            http_headers['Content-Type'] = content_type_header
        if amz_target_header:
            http_headers['X-Amz-Target'] = amz_target_header

        print_heading("http headers")
        for key, value in http_headers.items():
            print(key, ':', value)

    elif auth_type == AUTH_TYPE_GET_QUERY_STRING:
        http_headers = {}
        canonical_querystring += '&X-Amz-Signature=' + signature

    ############################################################
    # Step 6: Send the request
    ############################################################

    if http_method.lower() == 'get':
        request_url = endpoint + '?' + canonical_querystring
        r = requests.get(request_url, headers=http_headers)
    elif http_method.lower() == 'post':
        request_url = endpoint
        r = requests.post(request_url, data=payload, headers=http_headers)

    print_heading("request")
    print(request_url)
    print_heading("response")
    print('Response code: %d\n' % r.status_code)
    print(r.text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--example",   required=True, choices=[EXAMPLE_EC2_DESCRIBEREGIONS, EXAMPLE_DDB_CREATETABLE])
    parser.add_argument("-a", "--auth-type", required=True, choices=[AUTH_TYPE_GET_HEADER, AUTH_TYPE_GET_QUERY_STRING, AUTH_TYPE_POST_HEADER])
    args = parser.parse_args()
    main(args.example, args.auth_type)
