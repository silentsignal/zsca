Zero Trust SSH CA
=================

Experimental state, expect bugs, here's a quick demo setup, which already
presumes you have an Ed25519 keypair in the OpenPGP applet of the YubiKey
(see a detailed HOWTO at the end of this README),
`ykman` is installed in `$PATH`, and you are in a Python 3.5+ environment.

	$ git clone https://github.com/silentsignal/zsca
	...
	$ cd zsca
	$ pip install -r requirements.txt
	...
	$ python manage.py migrate
	...
	$ ykman openpgp attest sig sig-attest.pem
	...
	Enter PIN: <...>

(it might also as whether you want to overwrite certificate in that slot, but that's okay, just answer y)

	$ ykman openpgp export-certificate att att-attest.pem
	...
	$ python manage.py createsuperuser
	Username (leave blank to use 'dnet'):
	Email address: vsza@silentsignal.hu
	Password:
	Password (again):
	Superuser created successfully.
	$ python manage.py import_pubkey --user-email vsza@silentsignal.hu --attested-by {att,sig}-attest.pem
	<PublicKey: SHA256:UhG...Rg=> stored successfully, certificates for this key can be signed using the following command

	python manage.py sign_cert 1

	You can also create a CA based on this key by running

	python manage.py create_ca 1
	$ python manage.py create_ca 1
	$ ssh-keygen -t ed25519 -f test
	Generating public/private ed25519 key pair.
	Enter passphrase (empty for no passphrase):
	Enter same passphrase again:
	Your identification has been saved in test
	Your public key has been saved in test.pub
	The key fingerprint is:
	SHA256:JflncFN+lDhJywgAhdBpjWol5ejUxvBzI4VbUfOgEKM dnet@negyhatvan
	...
	$ python manage.py import_pubkey test.pub
	<PublicKey: SHA256:Jfl...KM=> stored successfully, certificates for this key can be signed using the following command

	python manage.py sign_cert 2
	$ python manage.py sign_cert 2 --identity teszt --principal teszt@silentsignal.hu -O force-command=uname -O clear
	Password: 
	Signed user key /tmp/zsca-signcertbezofksj/subject-cert.pub: id "teszt" serial 48 for teszt@silentsignal.hu valid from 2021-11-07T21:31:00 to 2022-02-05T21:32:01
	ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2g...
	$ python manage.py trusted_ca_list
	ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPc25bfttB6URNpvMB2pvr2mo25ux8rWusU0MWH8begS

Now you can set the following in your `ssh_config`

	Host foo
	...
	CertificateFile /path/to/output-of-sign_cert
	IdentityFile test

If the output of `trusted_ca_list` gets added to `TrustedUserCAKeys` on `foo`
issuing the command `ssh foo` will result in the command `uname` being run
on that machine in the next 90 days.

Generating Ed25519 keypairs with GnuPG
--------------------------------------

Although ZSCA makes use of YubiKey-specific attestation mechanics, most of it
(including the instructions below) should work with any OpenPGP hardware token
that has Ed25519 capabilities.

1. First, run `gpg --edit-card`, this opens an interactive command prompt
2. Enter `admin` to enable administrative commands
3. Enter `key-attr` which allows you to change the key parameters
4. During the following three times two rounds, answer `ECC` and `25519` to
   set all three keys (signature key, encryption key, authentication key) to
   25519 (Curve25519 for encryption, Ed25519 for the other two)
5. Finally, enter `generate` to actually generate keypairs using the
   algorithms set in the previous step.

Fetching attestation certificates for YubiKey PIV keypairs
----------------------------------------------------------

As described in the example above, OpenPGP keypairs generated on YubiKeys can
have an attestation certificate which is then used by ZSCA to verify it being
eligible for high-privilege usage.

YubiKeys have another similar applet called PIV (used by [yubikey-agent][1]
et al) that also offers attestation, which ZSCA can consume just
like with OpenPGP keys. In this case, the following commands can be used,
assuming you already have `ykman` installed as described above for OpenPGP.

	$ ykman piv attest 9a sig-attest.pem
	...
	$ ykman piv export-certificate f9 att-attest.pem
	...
	$ python manage.py import_pubkey --user-email vsza@silentsignal.hu --attested-by att-attest.pem sig-attest.pem
	<PublicKey: SHA256:zhB...iA=> stored successfully, certificates for this key can be signed using the following command
	...


[1]: https://github.com/FiloSottile/yubikey-agent
