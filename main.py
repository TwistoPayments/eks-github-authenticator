import base64
import datetime
import logging.config
import os
import re
from textwrap import dedent

import boto3
from botocore.signers import RequestSigner
import requests
from flask import Flask, make_response, request
import yaml


SETTINGS_FILE = os.environ.get('SETTINGS_FILE', 'settings_example.yaml')
print('Using settings', SETTINGS_FILE)
"""
Use prefix for obfuscation. This should limit random attempts to break into
a publicly accessible service.
"""
URL_PREFIX = os.environ.get('URL_PREFIX', '/')
print('Using URL prefix', URL_PREFIX)


DEFAULT_EXPIRATION_SECONDS = 3600

"""
The Kubernetes token expiration should be shorter than the temporary STS
credentials to avoid unexpected rejections.
"""
EXPIRATION_BUFFER_SECONDS = 30

with open(SETTINGS_FILE) as f:
    config = yaml.safe_load(f)

print('Known roles:')
for role in config['roleMapping'].keys():
    print('-', role)
print('##########################')

app = Flask(__name__)
sts = boto3.client('sts')


@app.route(f'{URL_PREFIX}')
def index():
    return dedent('''
        You are not expected to use this service manually.

        Use the following command to get a kubectl token:

            twisto-eks token --role developer
    ''')


@app.route(f'{URL_PREFIX}/token', methods=['GET'])
def exchange_token():
    role = request.args.get('role')
    role_mapping = config['roleMapping'].get(role)
    if not role_mapping:
        return 'Unknown role.', 400

    auth = request.headers.get('Authorization')
    if not auth:
        return dedent('''
            Not authorized, supply your Github authentication.

            You can generate a token with the required permissions at:

            https://github.com/settings/tokens/new?scopes=read:org
        '''), 401

    gh_teams = requests.get('https://api.github.com/user/teams', headers={'Authorization': auth})

    if gh_teams.status_code == 401:
        resp = make_response(gh_teams.text)
        resp.headers['Content-Type'] = gh_teams.headers['Content-Type']
        return resp

    if gh_teams.status_code != 200:
        return 'Error communicating with Github', 503

    found_teams = [(team['organization']['login'], team['name']) for team in gh_teams.json()]
    authorized = (role_mapping['github']['organization'], role_mapping['github']['team']) in found_teams

    if not authorized:
        return 'Unauthorized for this role', 403

    gh_user = requests.get('https://api.github.com/user', headers={'Authorization': auth})
    if gh_user.status_code != 200:  # If the first request succeeded, we assume the others should be authorized as well
        return 'Error communicating with Github', 503

    user = gh_user.json()['login']
    session_name = user + '@users.noreply.github.com'
    expiration_time = config.get('expiration_seconds', DEFAULT_EXPIRATION_SECONDS)
    creds_resp = sts.assume_role(
        RoleArn=role_mapping['arn'],
        RoleSessionName=session_name,
        DurationSeconds=expiration_time + EXPIRATION_BUFFER_SECONDS,
    )

    app.logger.info(
        'Authenticated Github user %(user)s because he belongs '
        'to %(org)s/%(team)s and gave him temporary key %(key)s '
        'for role %(role)s',
        {
            'user': user,
            'org': role_mapping['github']['organization'],
            'team': role_mapping['github']['team'],
            'key': creds_resp['Credentials']['AccessKeyId'],
            'role': role_mapping['arn'],
        },
    )

    token = make_eks_token(role_mapping['region'], role_mapping['cluster_name'], creds_resp['Credentials'])

    return {
        "kind": "ExecCredential",
        "apiVersion": "client.authentication.k8s.io/v1alpha1",
        "spec": {},
        "status": {
            "expirationTimestamp": (datetime.datetime.utcnow()
                + datetime.timedelta(seconds=expiration_time)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "token": token,
        }
    }


def make_eks_token(region, cluster_name, creds):
    temporary_client = boto3.client(
        'sts',
        region_name=region,
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )

    # Custom headers are not available via Boto3. Using request signer from botocore.
    signer = temporary_client._request_signer
    params = {
        'method': 'GET',
        'url': 'https://sts.{}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15'.format(region),
        'body': {},
        'headers': {
            'x-k8s-aws-id': cluster_name,
        },
        'context': {}
    }

    signed_url = signer.generate_presigned_url(
        params,
        region_name=region,
        expires_in=0,
        operation_name=''
    )
    base64_url = base64.urlsafe_b64encode(signed_url.encode('utf-8')).decode('utf-8')

    # remove any base64 encoding padding:
    return 'k8s-aws-v1.' + re.sub(r'=*', '', base64_url)
