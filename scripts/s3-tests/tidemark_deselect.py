"""pytest plugin: deselect the exact tests named in $TIDEMARK_DESELECT_FILE.

pytest's own --deselect matches node ids by prefix, so deselecting `test_100_continue` would
also drop `test_100_continue_error_retry`. Lines are `module::test_name [reason]`; `#` comments.
"""

import os


def _names():
    path = os.environ.get("TIDEMARK_DESELECT_FILE")
    if not path:
        return set()
    out = set()
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                out.add(line.split()[0])
    return out


def pytest_collection_modifyitems(config, items):
    names = _names()
    if not names:
        return
    keep, drop = [], []
    for item in items:
        module = os.path.splitext(os.path.basename(str(item.fspath)))[0]
        (drop if f"{module}::{item.name}" in names else keep).append(item)
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = keep
