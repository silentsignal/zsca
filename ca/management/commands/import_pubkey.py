# -*- encoding: utf-8 -*-

from argparse import FileType
from base64 import b64decode
from io import BytesIO

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db import transaction

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from ca.models import Attestation, YubiKey, PublicKey, read_ssh_string, read_yubikey_serial

class Command(BaseCommand):
    help = 'Imports a public key'

    def add_arguments(self, parser):
        parser.add_argument('key_or_cert', type=FileType('rb'))
        parser.add_argument(
                '--attested-by',
                type=FileType('rb'),
                metavar='att.pem',
                help='Provide an attestation certificate chain',
                )
        parser.add_argument(
                '--user-email',
                metavar='user@example.com',
                help='Assign user by email address',
                )

    def handle(self, *args, **options):
        with transaction.atomic():
            att_cert = options['attested_by']
            leaf_cert = options['key_or_cert']
            be = default_backend()
            certdata = leaf_cert.read()
            try:
                cert = x509.load_pem_x509_certificate(certdata, be)
                ssh_str = cert.public_key().public_bytes(
                        format=serialization.PublicFormat.OpenSSH,
                        encoding=serialization.Encoding.OpenSSH)
            except ValueError:
                cert = None
                ssh_str = certdata
            (ssh_type, ssh_b64) = ssh_str.split(b" ")[:2]
            ssh_raw = b64decode(ssh_b64)
            inner_type = read_ssh_string(BytesIO(ssh_raw))
            assert ssh_type == inner_type, "{0!r} != {1!r}".format(ssh_type, inner_type)
            pk = PublicKey.objects.create(key=ssh_raw)
            if cert is None:
                if att_cert:
                    raise ValueError("The --attested-by option is incompatible "
                            "with SSH public key format, use the X.509 PEM file instead")
                else:
                    print(repr(pk) + " stored successfully, certificates for "
                            "this key can be signed using the following command\n\n"
                            "python manage.py sign_cert " + str(pk.pk))
            else:
                if not att_cert:
                    raise ValueError("Providing an X.509 PEM file doesn't "
                            "make sense without an attestation chain, "
                            "did you forget --attested-by?")
                icert = x509.load_pem_x509_certificate(att_cert.read(), be)
                serial = read_yubikey_serial(cert)
                try:
                    yk = YubiKey.objects.get(serial=serial)
                except YubiKey.DoesNotExist:
                    yk = YubiKey.objects.create(serial=serial)
                email = options['user_email']
                if email:
                    user = User.objects.get(email=email)
                else:
                    user = Attestation.objects.filter(yubikey=yk).order_by('pk').last()
                (icert_der, cert_der) = (c.public_bytes(
                    encoding=serialization.Encoding.DER) for c in [icert, cert])
                att = Attestation.objects.create(pubkey=pk, yubikey=yk, user=user,
                        intermediate_cert=icert_der, leaf_cert=cert_der)
                att.validate()
                print(repr(pk) + " stored successfully, certificates for "
                        "this key can be signed using the following command\n\n"
                        "python manage.py sign_cert " + str(pk.pk) + "\n\n"
                        "You can also create a CA based on this key by running\n\n"
                        "python manage.py create_ca " + str(att.pk))
