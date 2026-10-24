#!/usr/bin/env python3
"""Generate native Shadowrocket lists; preserve unsupported regex separately.
Only flat, positive, OR-combined sing-box source rules are accepted.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import time
from urllib.request import Request, urlopen

REPO = 'MetaCubeX/meta-rules-dat'
SOURCES = {
    'GeositeCN': 'geo/geosite/cn.json',
    'GeoIPCN': 'geo/geoip/cn.json',
    'Geolocation-!CN': 'geo/geosite/geolocation-!cn.json',
}
ALLOWED = {'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr'}


def download(url):
    for attempt in range(4):
        try:
            req = Request(url, headers={'User-Agent': 'shadowrocket-rules-converter'})
            with urlopen(req, timeout=90) as response:
                data = response.read(64 * 1024 * 1024 + 1)
            if len(data) > 64 * 1024 * 1024:
                raise ValueError('Source exceeds size limit')
            return data
        except Exception:
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)


def convert(document):
    if document.get('version') not in (1, 2, 3, 4):
        raise ValueError('Unsupported source version')
    if set(document) - {'version', 'rules'}:
        raise ValueError('Unexpected document fields')
    rules = document.get('rules')
    if not isinstance(rules, list) or not rules:
        raise ValueError('Missing/empty rules')
    lines, regexes = set(), set()
    counts = {}
    for rule in rules:
        if not isinstance(rule, dict) or not rule or set(rule) - ALLOWED:
            raise ValueError('Unsupported rule structure; refusing to flatten logical/negative rules')
        # Multiple fields within this group are OR-combined by sing-box.
        for field, values in rule.items():
            if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
                raise ValueError('Invalid values for ' + field)
            counts[field] = counts.get(field, 0) + len(values)
            for value in values:
                if '\n' in value or '\r' in value:
                    raise ValueError('Line break in rule value')
                if field == 'domain_regex':
                    regexes.add(value)
                    continue
                if ',' in value:
                    raise ValueError('Comma in native rule value')
                if field == 'domain':
                    lines.add('DOMAIN,' + value)
                elif field == 'domain_suffix':
                    if value.startswith('.'):
                        # sing-box leading dot excludes the bare parent domain.
                        lines.add('DOMAIN-WILDCARD,*' + value)
                    else:
                        lines.add('DOMAIN-SUFFIX,' + value)
                elif field == 'domain_keyword':
                    lines.add('DOMAIN-KEYWORD,' + value)
                elif field == 'ip_cidr':
                    network = ipaddress.ip_network(value, strict=True)
                    # Shadowrocket IP-CIDR supports both IPv4 and IPv6.
                    lines.add('IP-CIDR,' + str(network))
    if not lines:
        raise ValueError('No supported native rules generated')
    return sorted(lines), sorted(regexes), counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='rules')
    parser.add_argument('--allow-unconverted-regex', action='store_true',
                        help='Explicitly permit a compatibility list with archived, inactive regex rules')
    args = parser.parse_args()
    # Pin all three downloads to one upstream commit for consistency.
    info = json.loads(download('https://api.github.com/repos/' + REPO + '/commits/sing'))
    commit = info['sha']
    prepared = {}
    report = {'upstream_repository': REPO, 'upstream_commit': commit,
              'mode': 'native-compatibility; archived regex rules are NOT active', 'sets': {}}
    warnings = []
    for name, source in SOURCES.items():
        url = 'https://raw.githubusercontent.com/' + REPO + '/' + commit + '/' + source
        raw = download(url)
        lines, regexes, counts = convert(json.loads(raw))
        if regexes and not args.allow_unconverted_regex:
            raise ValueError(f'{name}: {len(regexes)} unsupported regex rules; no outputs written. '
                             'Use --allow-unconverted-regex only after accepting this limitation.')
        header = ['# Generated from ' + url,
                  '# Native Shadowrocket rules; policy is supplied by RULE-SET in the main config.']
        if regexes:
            header.append(f'# WARNING: {len(regexes)} domain_regex rules are NOT active; see {name}.unconverted.json')
            warnings.append(f'{name}: {len(regexes)} domain_regex rules archived, NOT active')
        prepared[name + '.list'] = '\n'.join(header + lines) + '\n'
        if regexes:
            prepared[name + '.unconverted.json'] = json.dumps(
                {'warning': 'These regex rules are archived only and NOT active in Shadowrocket.',
                 'source': url, 'domain_regex': regexes}, ensure_ascii=False, indent=2) + '\n'
        report['sets'][name] = {'source_url': url,
                               'source_sha256': hashlib.sha256(raw).hexdigest(),
                               'source_counts': counts, 'native_rule_count': len(lines),
                               'unconverted_regex_count': len(regexes)}
    # Validate all sets before replacing any generated files.
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    prepared['conversion-report.json'] = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    for name, content in prepared.items():
        temporary = output / (name + '.tmp')
        temporary.write_text(content, encoding='utf-8')
        temporary.replace(output / name)
    # Remove stale archives when an upstream set no longer contains regex rules.
    for name in SOURCES:
        archive = output / (name + '.unconverted.json')
        if archive.name not in prepared and archive.exists():
            archive.unlink()
    for warning in warnings:
        print('::warning::' + warning)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
