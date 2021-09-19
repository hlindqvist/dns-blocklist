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

import dataset

import dns.zone
import dns.rdataset

import rndc

default_blocklists = [
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
        'regex': r'^0\.0\.0\.0 (\S+)',
        'etag': None,
        'zonename': 'hosts.stevenblack.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'zonename': 'simpletracking.disconnectme.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'zonename': 'simplead.disconnectme.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt',
        'regex': r'^\|\|([^\s/^]+)',
        'etag': None,
        'zonename': 'adblocknocoin.hoshsadiq.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://urlhaus.abuse.ch/downloads/rpz/',
        'regex': r'^(.*?) CNAME',
        'etag': None,
        'zonename': 'urlhaus.abusech.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'zonename': 'notrack-blocklist.quidsup.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://v.firebog.net/hosts/AdguardDNS.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'zonename': 'adguard.firebog.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://v.firebog.net/hosts/Easyprivacy.txt',
        'regex': r'^(?!#)(\S+)',
        'etag': None,
        'zonename': 'easyprivacy.firebog.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=rpz&showintro=0&mimetype=plaintext',
        'regex': r'^(.*?) A',
        'etag': None,
        'zonename': 'pgl.yoyo.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/KADhosts/hosts',
        'regex': r'^0\.0\.0\.0 (\S+)',
        'etag': None,
        'zonename': 'kadhosts.stevenblack.rpz.qw.se',
        'serial': 1
    },
    {
        'url': 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
        'regex': r'^0\.0\.0\.0 (\S+)',
        'etag': None,
        'zonename': 'adservers.anudeepnd.rpz.qw.se',
        'serial': 1
    }
]

zone_directory = "." #"/var/named/rpz"

rpz_nxdomain = dns.rdataset.from_text('IN', 'CNAME', 60, '.')


db = dataset.connect('sqlite:///dns-blocklists.db')

if 'blocklists' not in db.tables:
    for bl in default_blocklists:
        db['blocklists'].insert(bl)


for bl in db['blocklists'].all():
    headers = {'If-None-Match': bl['etag']}
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
    db['blocklists'].update(bl, ['url'])
