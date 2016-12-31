import sys
import configparser
import json
from datetime import datetime
from hashlib import sha256
import hmac
import requests
from fetch import get_credentials, get_signature_key

verify_ssl = True


def amz_request(s, method, url, payload, canonical_querystring):
    service = 'cognito-sync'
    host = 'cognito-sync.ap-northeast-1.amazonaws.com'
    region = 'ap-northeast-1'
    endpoint = 'https://cognito-sync.ap-northeast-1.amazonaws.com'
    content_type = 'application/x-amz-json-1.0'
    canonical_uri = '/identitypools/ap-northeast-1%3Afd52b510-f304-45fc-8838-c9e348c4a643/identities/ap-northeast-1%3A' + url
    if payload is None:
        parameters = ''.encode('utf-8')
        target = 'AWSCognitoSyncService.ListRecords'
    else:
        parameters = json.dumps(payload).encode('utf-8')
        target = 'AWSCognitoSyncService.UpdateRecords'

    t = datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')
    canonical_headers = '\n'.join(['host:' + host,
                                   'x-amz-date:' + amz_date,
                                   'x-amz-security-token:' + token,
                                   'x-amz-target:' + target + '\n'])
    signed_headers = 'host;x-amz-date;x-amz-security-token;x-amz-target'
    payload_hash = sha256(parameters).hexdigest()
    canonical_request = '\n'.join([method, canonical_uri, canonical_querystring,
                                   canonical_headers, signed_headers, payload_hash]).encode('utf-8')
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = '/'.join([date_stamp, region, service, 'aws4_request'])
    string_to_sign = '\n'.join(
        [algorithm, amz_date, credential_scope, sha256(canonical_request).hexdigest()]).encode('utf-8')
    signing_key = get_signature_key(secret, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign, sha256).hexdigest()
    auth_header = (algorithm + ' ' + 'Credential=' + access + '/' + credential_scope + ', ' +
                   'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature)

    amz_headers = {
        'User-Agent': 'aws-sdk-android/2.2.8 Linux/3.10.73 Dalvik/2.1.0/0 zh_CN com.amazonaws.mobileconnectors.cognito.CognitoSyncManager/2.2.8',
        'Connection': 'Keep-Alive',
        'Content-Type': content_type,
        'Accept-Encoding': 'gzip',
        'X-Amz-Date': amz_date,
        'X-Amz-Target': target,
        'x-amz-security-token': token,
        'Authorization': auth_header,
    }
    try:
        print('Requesting ' + url + '...', end="")
        if method is 'POST':
            r = s.post(endpoint + canonical_uri.replace('%3A', ':'), data=parameters, headers=amz_headers,
                       verify=verify_ssl)
        else:
            r = s.get(endpoint + canonical_uri.replace('%3A', ':') + '?' + canonical_querystring, headers=amz_headers,
                      verify=verify_ssl)
        if r.status_code == 200:
            print('\tOK')
            return r
        else:
            print('Response code:' % r.status_code)
    except:
        sys.exit(-1)


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read("fetch.ini")
    user_id = config['fetch']['user_id']
    last_sync_count = config['calendar']['last_sync_count']

    with open('calendar.csv', 'r') as f:
        dates = f.read().splitlines()

    access, secret, token = get_credentials(user_id)
    if access is None or secret is None:
        print('No key is available.')
        sys.exit(-1)

    s = requests.Session()
    r = amz_request(s, 'GET', user_id + '/datasets/calendar/records',
                    None, 'lastSyncCount=' + last_sync_count + '&maxResults=1024')
    dic = r.json()
    sync_token = dic['SyncSessionToken']
    payload = {'SyncSessionToken': sync_token, 'RecordPatches': []}
    for date in dates:
        payload['RecordPatches'].append({
            'Op': 'replace',
            'Key': date,
            'Value': '1',
            'SyncCount': int(last_sync_count),
            'DeviceLastModifiedDate': round(datetime.now().timestamp(), 3)})
    r = amz_request(s, 'POST', user_id + '/datasets/calendar', payload, '')
    dic = r.json()
    config.set('calendar', 'last_sync_count', str(dic['Records'][0]['SyncCount']))
    with open('fetch.ini', 'w+') as file:
        config.write(file)
    print('Done.')
