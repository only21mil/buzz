"""Explicit ignored-test admission; source and executable discovery fail closed."""
import csv
from pathlib import Path
import re
try:
    import tomllib
except ModuleNotFoundError:  # Existing macOS development hosts may use Python 3.9.
    tomllib = None

from postgres_test_source import (BARE_IGNORE_ATTRIBUTE, IGNORE_ATTRIBUTE, FUNCTION, ignore_attributes,
                                  module_ranges, sanitize_rust)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'scripts/postgres-tests.tsv'
FIELDS = ('package', 'binary', 'test', 'source', 'mode', 'reason')


def package_name(crate):
    source = (crate / 'Cargo.toml').read_text()
    if tomllib is not None:
        return tomllib.loads(source)['package']['name']
    package = re.search(r'(?ms)^\[package\]\s*\n(.*?)(?=^\[|\Z)', source)
    name = re.search(r'''(?m)^name\s*=\s*(["'])([^"']+)\1\s*(?:#.*)?$''',
                     package.group(1) if package else '')
    if name is None:
        raise ValueError(f'cannot read package name: {crate}')
    return name.group(2)


def source_tests(root):
    """Inventory every real ignore attribute, including bare and raw strings.

    Match source-local names separately from compiled names: Rust #[path]
    modules need not match filenames. Compiled reconciliation checks full names.
    """
    result = {}
    for path in sorted((root / 'crates').rglob('*.rs')):
        source = path.read_text()
        sanitized = sanitize_rust(source)
        ranges = module_ranges(source)
        attrs = ignore_attributes(source, sanitized)
        if len(attrs) != len(list(IGNORE_ATTRIBUTE.finditer(sanitized))):
            raise ValueError(f'unsupported ignore attribute: {path}')
        attrs += [(m.start(), m.end(), '') for m in BARE_IGNORE_ATTRIBUTE.finditer(sanitized)]
        for start, end, reason in attrs:
            function = FUNCTION.search(sanitized, end)
            if function is None:
                raise ValueError(f'ignored attribute without function: {path}')
            local = '::'.join([name for lo, hi, name in ranges if lo < start < hi]
                              + [function.group('name')])
            key = (str(path.relative_to(root)), local)
            if key in result:
                raise ValueError(f'ambiguous ignored source test: {key}')
            result[key] = reason
    return result


def read_inventory(root=ROOT, manifest=None):
    path = manifest or root / 'scripts/postgres-tests.tsv'
    with path.open(newline='') as stream:
        reader = csv.DictReader(stream, delimiter='\t')
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError('invalid PostgreSQL inventory columns')
        rows = list(reader)
    seen = set()
    for row in rows:
        key = (row['binary'], row['test'])
        if key in seen or row['mode'] not in ('desired', 'migration', 'external'):
            raise ValueError(f'duplicate or invalid PostgreSQL classification: {key}')
        if not row['reason']:
            raise ValueError(f'missing fixture classification reason: {key}')
        seen.add(key)
    return rows


def validate(root=ROOT, manifest=None):
    rows = read_inventory(root, manifest)
    sources = source_tests(root)
    covered = set()
    for row in rows:
        matches = [key for key in sources if key[0] == row['source']
                   and (row['test'] == key[1] or row['test'].endswith('::' + key[1]))]
        if len(matches) != 1 or matches[0] in covered:
            raise ValueError(f'stale or ambiguous inventory entry: {row["source"]} {row["test"]}')
        covered.add(matches[0])
        path = root / row['source']
        crate = next(parent for parent in path.parents if (parent / 'Cargo.toml').is_file())
        package = package_name(crate)
        binary = path.stem if path.parent == crate / 'tests' else package.replace('-', '_')
        if (row['package'], row['binary']) != (package, binary):
            raise ValueError(f'wrong package/target: {row["source"]}')
    missing = sources.keys() - covered
    if missing:
        raise ValueError('unclassified ignored tests: ' + ', '.join(f'{p}:{n}' for p, n in sorted(missing)))
    return rows


def binary_name(path):
    # Cargo libtest artifact suffix is hexadecimal, never a broad prefix match.
    return re.sub(r'-[0-9a-f]+$', '', Path(path).name).replace('-', '_')


def classify(test, binary=None, rows=None):
    rows = read_inventory() if rows is None else rows
    matches = [r for r in rows if r['test'] == test
               and (binary is None or r['binary'] == binary_name(binary))]
    if len(matches) != 1:
        raise ValueError(f'unknown or ambiguous ignored test: {binary_name(binary) if binary else "*"} {test}')
    return matches[0]['mode']


def reconcile(binary, tests, rows):
    expected = {r['test'] for r in rows if r['binary'] == binary_name(binary)}
    actual = set(tests)
    if not expected or actual != expected or len(tests) != len(actual):
        raise ValueError(f'compiled discovery mismatch for {binary_name(binary)}: '
                         f'missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}')
    return [(test, classify(test, binary, rows)) for test in tests]
