from __future__ import annotations
from ._store import base64, hashlib, subprocess, json, urllib, KEYMAN, KeymanExportError, exchange_session, export_credential, Refusal, fail, skeleton_path, keyman_service

SEED_ATTEMPTED = False

def derivation(raw, salt):
    return base64.b64encode(hashlib.pbkdf2_hmac('sha256', raw, salt, 100000, 32)).decode('ascii')

def skeleton_password():
    try:
        secret = bytearray(skeleton_path().read_bytes())
    except OSError:
        fail('skeleton', 'skeleton-key-unavailable')
    try:
        if secret.endswith(b'\n'):
            del secret[-1:]
        if not secret:
            fail('skeleton', 'skeleton-key-empty')
        return derivation(secret, b'homeserver_backblaze_restic_v2')
    finally:
        secret[:] = b'\0' * len(secret)

def credentials(bucket):
    try:
        return export_credential(keyman_service(bucket))
    except KeymanExportError as error:
        fail('keyman', 'keyman-' + error.signal)

def seed(bucket, key_id, application_key):
    global SEED_ATTEMPTED
    values = [key_id.encode('utf-8'), application_key.encode('utf-8')]
    if any(not x or len(x) > 511 or any(c in x for c in (0,10,13,34)) for x in values):
        fail('keyman', 'credential-invalid')
    material = bytearray(b'username="' + values[0] + b'"\npassword="' + values[1] + b'"\n')
    service = keyman_service(bucket)
    try:
        with exchange_session(native=True):
            SEED_ATTEMPTED = True
            proc = subprocess.run([KEYMAN, 'newkey', '--stdin', '--replace', service], input=bytes(material),
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12, check=False)
        result = json.loads(proc.stdout)
        if proc.returncode or not isinstance(result, dict) or result.get('ok') is not True or result.get('operation') != 'newkey' or result.get('service') != service or result.get('secret_free') is not True:
            fail('keyman', 'keyman-seed-refused')
    except KeymanExportError as error:
        fail('keyman', 'keyman-' + error.signal)
    except subprocess.TimeoutExpired:
        fail('keyman', 'keyman-seed-deadline-may-have-committed-retry-replace')
    except (OSError, ValueError, subprocess.SubprocessError):
        fail('keyman', 'keyman-seed-unavailable')
    finally:
        material[:] = b'\0' * len(material)
    return service

def authorize(bucket, key_id, application_key, *, mutating=False):
    try:
        basic = base64.b64encode((key_id + ':' + application_key).encode()).decode('ascii')
        request = urllib.request.Request('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', headers={'Authorization':'Basic '+basic})
        with urllib.request.urlopen(request, timeout=6) as response:
            auth = json.load(response)
        api = auth['apiUrl']
        token = auth['authorizationToken']
        account = auth['accountId']
        if (not isinstance(api, str) or urllib.parse.urlsplit(api).scheme != 'https' or
                not urllib.parse.urlsplit(api).hostname or
                not isinstance(token, str) or not token.strip() or token != token.strip() or
                not isinstance(account, str) or not account.strip() or account != account.strip()):
            fail('verify', 'b2-authorization-invalid')
        request = urllib.request.Request(api.rstrip('/')+'/b2api/v2/b2_list_buckets',
             data=json.dumps({'accountId':account,'bucketName':bucket}).encode(),
             headers={'Authorization':token,'Content-Type':'application/json'}, method='POST')
        with urllib.request.urlopen(request, timeout=6) as response:
            listing = json.load(response)
        if (not isinstance(listing, dict) or not isinstance(listing.get('buckets'), list) or
                any(not isinstance(item, dict) or not isinstance(item.get('bucketName'), str)
                    for item in listing['buckets'])):
            fail('verify', 'b2-listing-invalid')
        return any(item['bucketName'] == bucket for item in listing['buckets'])
    except urllib.error.HTTPError as error:
        if error.code in (401, 403) and not mutating:
            return False
        fail('verify', 'b2-check-unavailable')
    except Refusal:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        fail('verify', 'b2-check-unavailable')


