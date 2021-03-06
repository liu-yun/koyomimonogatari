import os
import sys
import configparser
import json
import calendar
from datetime import timedelta, datetime
from hashlib import sha256
import hmac
import requests

verify_ssl = True


def get_id():
    print('Requesting ID...', end="")
    cognito_url = 'https://cognito-identity.ap-northeast-1.amazonaws.com/'
    cognito_payload = {
        'IdentityPoolId': 'ap-northeast-1:fd52b510-f304-45fc-8838-c9e348c4a643',
        'Logins': {}
    }
    cognito_headers = {
        'User-Agent': 'aws-sdk-android/2.2.8 Linux/3.10.73 Dalvik/2.1.0/0 zh_CN',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'Content-Type': 'application/x-amz-json-1.0',
        'X-Amz-Target': 'AWSCognitoIdentityService.GetId'
    }
    try:
        r = requests.post(cognito_url, json=cognito_payload, headers=cognito_headers, verify=verify_ssl)
        if r.status_code == 200:
            print('\tOK')
            return r.json()['IdentityId'].lstrip('ap-northeast-1:')
    except:
        print('\nFailed to get ID')
        sys.exit(-1)


def get_credentials(user):
    print('Requesting credentials...', end="")
    cognito_url = 'https://cognito-identity.ap-northeast-1.amazonaws.com/'
    cognito_payload = {
        'IdentityId': 'ap-northeast-1:' + user,
        'Logins': {}
    }
    cognito_headers = {
        'User-Agent': 'aws-sdk-android/2.2.8 Linux/3.10.73 Dalvik/2.1.0/0 zh_CN',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'Content-Type': 'application/x-amz-json-1.0',
        'X-Amz-Target': 'AWSCognitoIdentityService.GetCredentialsForIdentity'
    }
    try:
        r = requests.post(cognito_url, json=cognito_payload, headers=cognito_headers, verify=verify_ssl)
        if r.status_code == 200:
            keys = r.json()
            print('\tOK')
            return keys['Credentials']['AccessKeyId'], keys['Credentials']['SecretKey'], keys['Credentials'][
                'SessionToken']
    except:
        print('\nFailed to get credentials')
        sys.exit(-1)


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    region = sign(date, region_name)
    service = sign(region, service_name)
    signing = sign(service, 'aws4_request')
    return signing


def get_amz_request():
    def amz_request_wrapper(session, function, payload):
        method = 'POST'
        service = 'lambda'
        host = 'lambda.ap-northeast-1.amazonaws.com'
        region = 'ap-northeast-1'
        endpoint = 'https://lambda.ap-northeast-1.amazonaws.com'
        content_type = 'binary/octet-stream'
        target = 'AWSLambda.Invoke'
        invocation_type = 'RequestResponse'
        canonical_uri = '/2015-03-31/functions/koyomimonogatari_app_' + function + '_get/invocations'
        parameters = json.dumps(payload).encode('utf-8')

        t = datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')
        canonical_querystring = ''
        canonical_headers = '\n'.join(['host:' + host,
                                       'x-amz-client-context:' + context,
                                       'x-amz-date:' + amz_date,
                                       'x-amz-invocation-type:' + invocation_type,
                                       'x-amz-log-type:' + 'None',
                                       'x-amz-security-token:' + token,
                                       'x-amz-target:' + target + '\n'])
        signed_headers = ('host;x-amz-client-context;x-amz-date;x-amz-invocation-type;'
                          'x-amz-log-type;x-amz-security-token;x-amz-target')
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
            'User-Agent': 'aws-sdk-android/2.2.8 Linux/3.10.73 Dalvik/2.1.0/0 zh_CN',
            'Connection': 'Keep-Alive',
            'Content-Type': content_type,
            'Accept-Encoding': 'gzip',
            'X-Amz-Date': amz_date,
            'X-Amz-Target': target,
            'X-Amz-Client-Context': context,
            'X-Amz-Invocation-Type': invocation_type,
            'X-Amz-Log-Type': 'None',
            'x-amz-security-token': token,
            'Authorization': auth_header,
        }
        try:
            print('Requesting ' + function + '...', end="", flush=True)
            r = session.post(endpoint + canonical_uri, data=parameters, headers=amz_headers, verify=verify_ssl)
            if r.status_code == 200:
                print('\tOK')
                return r
            else:
                print('Response code:' % r.status_code)
        except:
            sys.exit(-1)

    return amz_request_wrapper


def transform_url(url):
    return url.lstrip('/').replace('/', '\\')


def cf_get(s, url):
    cf_url = "https://d3249smwmt8hpy.cloudfront.net" + url
    try:
        file_path = transform_url(url)
        if os.path.isfile(file_path) is True:
            return
        print('Requesting ' + url, end="", flush=True)
        d = s.get(cf_url, verify=verify_ssl)
        if d.status_code == 200:
            if os.path.exists(os.path.dirname(file_path)) is False:
                os.makedirs(os.path.dirname(file_path))
            with open(file_path, 'wb+') as f:
                for chunk in d:
                    f.write(chunk)
            print('\tOK')
        if d.status_code == 403:
            print('\n403 Forbidden.')
            raise requests.HTTPError()
        if os.path.split(file_path)[1] == 'android.m3u8':
            cf_get(s, os.path.dirname(url) + '/' + d.text.splitlines()[2])
        if os.path.split(file_path)[1] == 'movie_.m3u8':
            last = int(d.text.splitlines()[-2].rstrip('.ts').lstrip('movie_'))
            video_list = [os.path.dirname(url) + '/movie_' + str(i).zfill(5) + '.ts' for i in range(last + 1)]
            video_list.append(os.path.dirname(url) + '/vdata')
            for video in video_list:
                cf_get(s, video)
    except requests.HTTPError:
        print('Failed to get ' + url)
        sys.exit(-1)


def unique(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


if __name__ == '__main__':
    print('Koyomimonogatari Fetch')
    folders = ['teaser', 'movie', 'calendar', 'monthlygift', 'json\\calendar', 'json\\monthlygift',
               'json\\monthlygift\\complete']
    for folder in folders:
        if os.path.exists(folder) is False:
            os.makedirs(folder)

    with open('context', 'r') as f:
        context = f.read()
    config = configparser.ConfigParser()
    if os.path.exists('fetch.ini') is False:
        user_id = get_id()
        config['fetch'] = {'last_modified': '2015/12/31',
                           'last_news_updated': '2015/12/31',
                           'last_movie_fetched': '0',
                           'teaser_fetched': False,
                           'user_id': user_id}
        with open('fetch.ini', 'w') as file:
            config.write(file)
    config.read("fetch.ini")
    date_last_modified = datetime.strptime(config['fetch']['last_modified'], "%Y/%m/%d").date()
    date_last_news_updated = datetime.strptime(config['fetch']['last_news_updated'], "%Y/%m/%d").date()
    last_movie_fetched = config['fetch']['last_movie_fetched']
    teaser_fetched = config['fetch'].getboolean('teaser_fetched')
    user_id = config['fetch']['user_id']

    access, secret, token = get_credentials(user_id)
    if access is None or secret is None:
        print('No key is available.')
        sys.exit(-1)
    amz_request = get_amz_request()

    s = requests.Session()
    amz_payload = {
        'os': 'android',
        'version': '1.0.6',
        'build_no': '20',
        'user_id': user_id,
        'width': 1920,
        'height': 1080,
        'scale': 1
    }
    url_list = []

    r = amz_request(s, 'config', amz_payload)
    dic = r.json()
    str_today = dic['today']
    str_news_updated = dic['news_updated_at']
    date_today = datetime.strptime(str_today, "%Y/%m/%d").date()
    date_news_updated = datetime.strptime(str_news_updated, "%Y/%m/%d").date()
    if date_today <= date_last_modified:
        print('Already up-to-date.')
        sys.exit()
    if teaser_fetched is False:
        url_list.append(dic['teaser_calendar_image_url'])
        url_list.append(dic['teaser_image_url'])
        url_list.append(dic['teaser_voice_url'])
    with open('json\\config.json', 'w+', encoding='utf-8') as f:
        f.write(r.text)

    r = amz_request(s, 'auth', amz_payload)
    dic = r.json()
    cf_policy, cf_signature, cf_key_pair = dic['p'], dic['s'], dic['k']

    r = amz_request(s, 'movie', amz_payload)
    dic = r.json()
    movie_modified = False
    for movie in dic['movies']:
        if int(movie['id']) > int(last_movie_fetched):
            url_list.append(movie['movie_url'].split('net')[1])
            url_list.append(movie['image_url'])
            movie_modified = True
            last_movie_fetched = str(movie['id'])
    if movie_modified is True:
        with open('json\\movie.json', 'w+', encoding='utf-8') as f:
            f.write(r.text)
        config.set('fetch', 'last_movie_fetched', last_movie_fetched)

    if date_news_updated > date_last_news_updated:
        r = amz_request(s, 'news', amz_payload)
        with open('json\\news.json', 'w+', encoding='utf-8') as f:
            f.write(r.text)
        config.set('fetch', 'last_news_updated', str_news_updated)

    start_date = date_last_modified + timedelta(days=1)
    delta = date_today - start_date
    amz_payload['days'] = [(start_date + timedelta(days=i)).strftime("%Y/%m/%d") for i in range(delta.days + 1)]
    r = amz_request(s, 'dailycalendar', amz_payload)
    dic = r.json()
    del amz_payload['days']
    for day in dic['days']:
        url_list.append(day['image_url'])
        url_list.append(day['voice_url'])
        with open('json\\calendar\\' + day['month'].zfill(2) + day['date'].zfill(2) + '.json', 'w+',
                  encoding='utf-8') as f:
            f.write(json.dumps(day, ensure_ascii=False))
        # Rewards
        if day['rewards'] is not None:
            rewards = json.loads(day['rewards'].strip('[]'))
            url_list.append(rewards['thumbnail_url'])
            url_list.append(rewards['image_url'])
        # Monthly gifts
        if int(day['date']) == calendar.monthrange(int(day['year']), int(day['month']))[1]:
            amz_payload['date'] = day['key'][:7]
            r = amz_request(s, 'monthlygift', amz_payload)
            dic = r.json()
            del amz_payload['date']
            url_list.append(dic['thumbnail_url'])
            url_list.append(dic['image_url'])
            with open('json\\monthlygift\\' + dic['date'][5:] + '.json', 'w+', encoding='utf-8')as f:
                f.write(r.text)

    days = range(1, 367)
    for day in days:
        amz_payload['days'] = day
        r = amz_request(s, 'completeinfo', amz_payload)
        dic = r.json()
        url_list.append(dic['image_url'])
        if dic['gift'] is True:
            url_list.append(dic['gift_thumbnail_url'])
            url_list.append(dic['gift_image_url'])
        with open('json\\monthlygift\\complete\\' + str(dic['days']) + '.json', 'w+', encoding='utf-8')as f:
            f.write(r.text)

    with requests.Session() as s:
        s.headers.update({
            'User-Agent': 'stagefright/1.2 (Linux;Android 6.0.1)',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
        })
        s.cookies.update({
            'CloudFront-Policy': cf_policy,
            'CloudFront-Signature': cf_signature,
            'CloudFront-Key-Pair-Id': cf_key_pair
        })
        for url in unique(url_list):
            cf_get(s, url)
    config.set('fetch', 'last_modified', str_today)
    with open('fetch.ini', 'w+') as file:
        config.write(file)
    print('Done.')
