#!/bin/bash
# Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

#
# This shell script demonstrates writing logs from machines
# and then reprocessing those logs to amalgamate python tracebacks
# into a single log entry in a new collection.
#
# To run this demo, first install the example applications:
#
#        go install tailscale.com/logtail/example/...
#
# Then generate a LOGTAIL_API_KEY and two test collections by visiting:
#
#        https://log.tailscale.io
#
# Then set the three variables below.
trap 'rv=$?; [ "$rv" = 0 ] || echo "-- exiting with code $rv"; exit $rv' EXIT
set -e

LOG_TEXT='server starting
config file loaded
answering queries
Traceback (most recent call last):
  File "/Users/crawshaw/junk.py", line 6, in <module>
    main()
  File "/Users/crawshaw/junk.py", line 4, in main
    raise Exception("oops")
Exception: oops'

die() {
	echo "$0: $*" >&2
	exit 1
}

msg() {
	echo "-- $*" >&2
}

if [ -z "$LOGTAIL_API_KEY" ]; then
	die "LOGTAIL_API_KEY is not set"
fi

if [ -z "$COLLECTION_IN" ]; then
	die "COLLECTION_IN is not set"
fi

if [ -z "$COLLECTION_OUT" ]; then
	die "COLLECTION_OUT is not set"
fi

# Private IDs are 32-bytes of random hex.
# Normally you'd keep the same private IDs from one run to the next, but
# this is just an example.
msg "Generating keys..."
privateid1=$(hexdump -n 32 -e '8/4 "%08X"' /dev/urandom)
privateid2=$(hexdump -n 32 -e '8/4 "%08X"' /dev/urandom)
privateid3=$(hexdump -n 32 -e '8/4 "%08X"' /dev/urandom)

# Public IDs are the SHA-256 of the private ID.
publicid1=$(echo -n $privateid1 | xxd -r -p - | shasum -a 256 | sed 's/ -//')
publicid2=$(echo -n $privateid2 | xxd -r -p - | shasum -a 256 | sed 's/ -//')
publicid3=$(echo -n $privateid3 | xxd -r -p - | shasum -a 256 | sed 's/ -//')

# Write the machine logs to the input collection.
# Notice that this doesn't require an API key.
msg "Producing new logs..."
echo "$LOG_TEXT" | logtail -c $COLLECTION_IN -k $privateid1 >/dev/null
echo "$LOG_TEXT" | logtail -c $COLLECTION_IN -k $privateid2 >/dev/null

# Adopt the logs, so they will be kept and are readable.
msg "Adopting logs..."
logadopt -p "$LOGTAIL_API_KEY" -c "$COLLECTION_IN" -m $publicid1
logadopt -p "$LOGTAIL_API_KEY" -c "$COLLECTION_IN" -m $publicid2

# Reprocess the logs, amalgamating python tracebacks.
#
# We'll take that reprocessed output and write it to a separate collection,
# again via logtail.
#
# Time out quickly because all our "interesting" logs (generated
# above) have already been processed.
msg "Reprocessing logs..."
logreprocess -t 3s -c "$COLLECTION_IN" -p "$LOGTAIL_API_KEY" 2>&1 |
  logtail -c "$COLLECTION_OUT" -k $privateid3
