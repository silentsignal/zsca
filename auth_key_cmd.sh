#!/bin/sh

# Usage: put the two lines below into the SSHd config
#
# AuthorizedKeysCommand /path/to/this/file %k %u
# AuthorizedKeysCommandUser <username>
#
# Don't forget to chmod it so that all parents are both writable only
# and owned by root, otherwise it won't be executed.

if [ "specal-username-comes-here" = "$2" ]; then
	cd /path/to/zsca
	. ../venv/bin/activate
	python manage.py latest_cert_for_pubkey $1
fi
