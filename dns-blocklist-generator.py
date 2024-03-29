#!/usr/bin/env python3
#
#   Copyright 2020 Hakan Lindqvist <dnstools@qw.se>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#


# WIP
#
# fetches block lists in various formats, reformats as RPZ zone data and loads into BIND with ixfr-from-differences for further IXFR/AXFRing
#


# run bind with something like
# ixfr-from-differences yes (or master)
# check-names ignore ?
# max-ixfr-ratio 30
# new-zones-directory
# tcp-clients 1024

import requests
import re
import os
import sys

import dataset

import dns.zone
import dns.rdataset

import rndc

default_blocklists = [
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
        'regex': r'^0\.0\.0\.0 (\S+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'hosts.stevenblack.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'simpletracking.disconnectme.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'simplead.disconnectme.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt',
        'regex': r'^\|\|([^\s/^]+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'adblocknocoin.hoshsadiq.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://urlhaus.abuse.ch/downloads/rpz/',
        'regex': r'^(.*?) CNAME',
        'etag': None,
        'last_modified': None,
        'zonename': 'urlhaus.abusech.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'notrack-blocklist.quidsup.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://v.firebog.net/hosts/AdguardDNS.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'adguard.firebog.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://v.firebog.net/hosts/Easyprivacy.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'easyprivacy.firebog.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=rpz&showintro=0&mimetype=plaintext',
        'regex': r'^(.*?) A',
        'etag': None,
        'last_modified': None,
        'zonename': 'pgl.yoyo.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/KADhosts/hosts',
        'regex': r'^0\.0\.0\.0 (\S+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'kadhosts.stevenblack.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
        'regex': r'^0\.0\.0\.0 (\S+)',
        'etag': None,
        'last_modified': None,
        'zonename': 'adservers.anudeepnd.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://rpz.oisd.nl/',
        'regex': r'^(.*?) CNAME',
        'etag': None,
        'last_modified': None,
        'zonename': 'rpz.oisd.nl.rpz.qw.se',
        'serial': 1
    }
]


zone_directory = sys.argv[1]

rpz_nxdomain = dns.rdataset.from_text('IN', 'CNAME', 60, '.')


db = dataset.connect('sqlite:///dns-blocklists.db')

if 'blocklists' not in db.tables:
    for bl in default_blocklists:
        if os.path.isfile(os.path.join(zone_directory, bl['zonename'])):
            print(bl['zonename'])
            original_zone = dns.zone.from_file(os.path.join(zone_directory, bl['zonename']), origin=bl['zonename'], relativize=False)
            oldsoa = next(original_zone.iterate_rdatas(rdtype=dns.rdatatype.SOA))
            bl['serial'] = oldsoa[2].serial
        db['blocklists'].insert(bl)


for bl in db['blocklists'].all():
    if 'etag' in bl:
        headers = {'If-None-Match': bl['etag']}
    elif 'last_modified' in bl:
        headers = {'If-Modified-Since': bl['last_modified']}
    r = requests.get(bl['url'], headers=headers)

    r.raise_for_status()

    if r.status_code == 304:
        print(f"{bl['url']} is already current")
        continue
    else:
        print(f"{bl['url']} requires updating")

    serial = bl['serial'] + 1

    zone = dns.zone.Zone(bl['zonename'])
    zone.replace_rdataset('@', dns.rdataset.from_text('IN', 'SOA', 7200, f"ns1.qw.se. hostmaster.qw.se. {serial} 3600 1800 3600000 7200"))
    zone.replace_rdataset('@', dns.rdataset.from_text('IN', 'NS', 7200, f"ns1.qw.se."))
    zone.replace_rdataset('_source', dns.rdataset.from_text('IN', 'TXT', 7200, f"\"Source: {bl['url']} (see this for copyright details)\""))

    for line in r.text.splitlines():
        m = re.search(bl['regex'], line)
        if m:
            if len(m.group(1)) > 253-len(bl['zonename']):
                print(f"Error: {m.group(1)} + {bl['zonename']} is too long")
                continue
            try:
                zone.replace_rdataset(m.group(1).strip(), rpz_nxdomain)
            except Exception:
                print(f"Error: {m.group(1)}")

    zone.to_file(os.path.join(zone_directory, bl['zonename']))

    # auto reload BIND stuff
    #rndc.call(f"reload zone {bl[zonename]}") #also addzone as necessary?

    bl['serial'] = serial
    if 'etag' in r.headers:
        bl['etag'] = r.headers['etag']
    elif 'last-modified' in r.headers:
        bl['last_modified'] = r.headers['last-modified']
    db['blocklists'].update(bl, ['url'])
