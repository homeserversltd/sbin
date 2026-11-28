"""Run an existing stop through the front door's resolution and loader."""


def run_stop(path, argv, **kwargs):
    from agathodaimon import cli

    target = cli._slash_target(path)
    if target is None or not target.is_file():
        raise LookupError(f"stop does not resolve: {path}")
    return cli._load(target).main(argv, **kwargs)
