# AWS Python Code Examples

## signin

### `generate_federated_signin_url.py`
- This script constructs a URL that gives you direct access to the AWS Management Console.
- This method was the initial solution (circa 2012) for granting your federated users access to the AWS Management Console and pre-dates SAML/OIDC federation. In AWS documentation, it is commonly referred to as the "Custom Identity Broker" federation pattern.
- Sing-In URL can only be generated using short-term AWS credentials retrieved from either `sts:AssumeRole` or `sts:GetFederationToken` API operations.
- Usage:
    - The script will first obtain credentials using the standard credential provider chain. It will then assume the specified role and use the returned credentials to generate the sign-in URL.
    - You can optionally provide profile name using `--profile`.
    ```bash
    ./generate_federated_signin_url.py \
        --role-name OrganizationAccountAccessRole \
        --account-id 123456789012
    ```
    - Provide credentials that will be used to generate sign-in URL directly.
    ```bash
    ./generate_federated_signin_url.py \
        --session-id $AWS_ACCESS_KEY_ID \
        --session-key $AWS_SECRET_ACCESS_KEY \
        --session-token $AWS_SESSION_TOKEN
    ```

- References:
    - [Enable Single Sign On to the AWS Management Console | AWS News Blog](https://aws.amazon.com/blogs/aws/enable-single-sign-on-to-the-aws-management-console/)
    - [Enabling custom identity broker access to the AWS console | AWS IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html)

## sigv4
Example code related to AWS Signature Version 4 generation

### `sigv4_sign.py`
- Illustrative code demonstrating step by step process of generating AWS requests signed using AWS Sigv4.
- Note: AWS credentials are pulled from the environment variables; only long-term credentials are supported
- Four examples are implemented:
    - "`EC2:DescribeRegions`" call using HTTP GET method and Authorization header to pass request signature
    - "`EC2:DescribeRegions`" call using HTTP GET method and query string to pass request signature (presigned URL)
    - "`EC2:DescribeRegions`" call using HTTP POST method and Authorization header to pass request signature
    - "`dynamodb:CreateTable`" call using HTTP POST method and Authorization header to pass request signature
- usage:
```bash
python sigv4_sign.py -e "ec2-describeregions" -a "get-header"
python sigv4_sign.py -e "ec2-describeregions" -a "get-query"
python sigv4_sign.py -e "ec2-describeregions" -a "post-header"
# !!! this request will result in DDB table creation if provided credentials have proper permission
python sigv4_sign.py -e "ddb-createtable" -a "post-header"
```


### `sigv4_sign_botocore.py`
- This script is similar to `sigv4_sign.py`, but utilizes botocore's SigV4Auth and AWSRequest classes.
- Showcases signing of the arbitrary AWS requests using botocore.
- Two examples are implemented:
    - "`EC2:DescribeRegions`" call using HTTP GET method and Authorization header to pass request signature
    - "`EC2:DescribeRegions`" call using HTTP POST method and Authorization header to pass request signature
- usage:
```bash
python sigv4_sign_botocore.py -a "get-header"
python sigv4_sign_botocore.py -a "post-header"
```


### `sigv4_s3_http_post.py`
- Showcases file upload directly to Amazon S3 through a browser using HTTP POST requests signed with AWS Signature Version 4.
- Notes:
    - AWS credentials are pulled from the environment variables; only long-term credentials are supported
    - S3 bucket must have ACL permissions enabled
- [Authenticating Requests in Browser-Based Uploads Using POST (AWS Signature Version 4) - Amazon Simple Storage Service](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-UsingHTTPPOST.html)
- usage:
```bash
python sigv4_s3_http_post.py -b "my-bucket-name" -r "us-east-1"
```
