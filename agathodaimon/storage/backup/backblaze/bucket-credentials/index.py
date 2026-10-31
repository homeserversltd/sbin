from agathodaimon.storage.backup.backblaze.shared import main_for

def main(argv=None):
    return main_for('bucket-credentials')

if __name__ == '__main__':
    raise SystemExit(main())
