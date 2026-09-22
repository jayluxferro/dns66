DNS-Based Host Blocking for Android
===================================
This is a DNS-based host blocker for Android. In the default configuration,
several widely-respected host files are used to block ads, malware, and other
weird stuff.

[![Build](https://github.com/jayluxferro/dns66/actions/workflows/build.yml/badge.svg)](https://github.com/jayluxferro/dns66/actions/workflows/build.yml)

This is a maintained fork of the original DNS66 by Julian Andres Klode
(https://github.com/julian-klode/dns66, now archived), kept current with
modern Android tooling and platform requirements.

Installing
----------
APKs are built automatically by GitHub Actions and published on the
[releases page](https://github.com/jayluxferro/dns66/releases): every push to
`main` produces debug and release APKs as build artifacts, and pushing a tag
like `v0.7.0` publishes a release with a signed APK (see below).

Building
--------
You need a JDK (17 or newer; 21 recommended) and an Android SDK with platform
36 installed. Then:

    ./gradlew assembleDebug      # debug APK
    ./gradlew assembleRelease    # unsigned release APK
    ./gradlew test               # unit tests

For release signing in CI, configure these repository secrets:
`KEYSTORE_BASE64` (base64-encoded keystore file), `KEYSTORE_PASSWORD`,
`KEY_ALIAS`, and `KEY_PASSWORD`. Without them, tag builds publish the unsigned
release APK.

Using it
---------
On a fresh install, no hosts files are downloaded yet: use the refresh action
in the toolbar menu to fetch them before the blocking becomes effective (the
Apps tab's list also supports pull-to-refresh for reloading the app list). On
the Hosts tab you can enable *automatically refresh hosts files* to have the
rule databases updated in the background via a scheduled job.

The first time you start the VPN, Android shows a connection request dialog
for the VPN permission. Starting on boot can be enabled on the Start tab
(*Resume on system start-up*), and the VPN notification supports pausing and
resuming.

Entries in the hosts and DNS servers lists can be reordered by long-pressing
and dragging them, and removed via the delete action in the entry editor. For
hosts, a later entry overrides a previous entry; for DNS servers, the first
server is preferred.

Besides hosts file URLs, hosts entries can be manual rules in three forms:
a plain hostname blocks exactly that host (`ads.example.com`), `*.example.com`
blocks the domain and all of its subdomains, and `regex:<pattern>` blocks
every host the regular expression matches (for example
`regex:^ads[0-9]+\.example\.com$`). Wildcard-style lists such as oisd's
`domainswild` are matched the same way, covering subdomains.

The default configuration ships six block lists - StevenBlack's unified
hosts (with oisd big, AdAway, Dan Pollock's, and Peter Lowe's lists alongside
a live malware feed from abuse.ch URLhaus) - all enabled out of the box.

Currently, there are some minor usability issues:

* If you change a setting, you must manually restart the VPN service
* There is no validation of input, so DNS servers that are not valid
  plain addresses, tls:// hosts, or https:// URLs are not rejected

How it works
------------
The app establishes a VPN service, with routes for all DNS servers diverted to
it. The VPN service then intercepts the packages for the servers and forwards
any DNS queries that are not blacklisted.

Custom upstream DNS can be configured, over IPv4 and IPv6. Encrypted
upstreams are supported as well: a DNS server location of the form
`tls://9.9.9.9` uses DNS over TLS (port 853 by default), and
`https://1.1.1.1/dns-query` uses DNS over HTTPS (RFC 8484); plain
`1.2.3.4[:port]` entries use ordinary UDP DNS. Encrypted connections are
pooled and reused across queries, and their traffic is kept out of the VPN.

The default configuration ships Cloudflare, Google, and Quad9 - including
their DNS over HTTPS variants and the security-filtered (malware / adult
content) options - with Cloudflare DoH enabled out of the box. If custom DNS
servers are turned off entirely, the current connection's DNS servers are
used over plain UDP.


Privacy Guarantee
-----------------
Privacy is the most important aspect of DNS66. DNS66 is strictly
data reducing: Running it can only reduce the amount of data leaving your
device, not increase it (except for fetching hosts files, obviously), as for
each request, we will either allow it to leave your device or not - we will
not send other requests or add other information to the request.

Two features can send additional data, and both are opt-in:

1. Automatic hosts file updates. When *automatically refresh hosts files*
   is enabled (off by default), your phone periodically contacts the servers
   the configured host lists live on. DNS66 includes only as much data as
   necessary to complete the request.

2. Logcat sharing. The *Send logcat* action in the toolbar menu shares the
   debug log through Android's standard share sheet. Debug logs may include
   personal information, and you should review them before sharing them
   publicly.

Contributing
------------
See [CONTRIBUTING.md](CONTRIBUTING.md)

License
-------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Parts of the program are licensed under only version 3 of the license, and
some parts might be licensed under the terms of other compatible licenses. See
the file [copyright](app/src/main/assets/copyright) for further (machine-readable) information.

Binaries also bundle external libraries. To the best of our knowledge those
are licensed under the Apache license, version 2.0, except for pcap4j, which
is licensed under the MIT license, and dnsjava, which uses a 3 clause BSD
license. See
the file [copyright.libraries](app/src/main/assets/copyright.libraries) for further (machine-readable) information.

Code of Conduct
---------------
Please note that this project is released with a Contributor Code of
Conduct. By participating in this project you agree to abide by its terms.

Authors
-------
Julian Andres Klode <jak@jak-linux.org>

Parts are derived from https://github.com/dbrodie/AdBuster by Daniel Brodie.

This fork is maintained by [jayluxferro](https://github.com/jayluxferro).
