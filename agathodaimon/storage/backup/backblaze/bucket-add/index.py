from agathodaimon.storage.backup.backblaze.shared import main_for
from agathodaimon.storage.backup.backblaze._store import fail, rows, keyman_service, valid_bucket
from agathodaimon.storage.backup.backblaze._keyman import authorize, seed


def act(verb, metadata, data, bucket):
    key_id, application_key = metadata.get('keyId'), metadata.get('applicationKey')
    if not isinstance(key_id, str) or not key_id or not isinstance(application_key, str) or not application_key:
        fail('shape', 'credential-invalid')
    existing = [row for row in rows(data, True) if row.get('bucket') == bucket]
    if verb == 'bucket-add' and existing:
        fail('config', 'bucket-already-exists')
    if verb == 'bucket-credentials' and len(existing) != 1:
        fail('config', 'bucket-not-configured')
    service = keyman_service(bucket)
    if any(isinstance(other := row.get('bucket'), str) and other != bucket and
           (other.replace('-', '_') == service or
            (valid_bucket(other) and keyman_service(other) == service))
           for row in rows(data)):
        fail('config', 'keyman-service-collision')
    if not authorize(bucket, key_id, application_key, mutating=True):
        fail('verify', 'bucket-not-visible-to-key')
    service = seed(bucket, key_id, application_key)
    if verb == 'bucket-add':
        rows(data, True).append({'bucket':bucket, 'prefix':'', 'items':[],
                                 'managers':{'forgejo':{'localNas':False,'backblazeBackup':False,'skip':[]}}})
    mutation_result = {'ok':True, 'keyman_service':service}
    return mutation_result

def main(argv=None):
    return main_for('bucket-add')

if __name__ == '__main__':
    raise SystemExit(main())
