from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat._der import DERReader, INTEGER

from django.db import models

from django.contrib.auth.models import User

# src: https://developers.yubico.com/PGP/Attestation.html
KEY_SOURCE  = x509.ObjectIdentifier("1.3.6.1.4.1.41482.5.2")
SERIAL_NO   = x509.ObjectIdentifier("1.3.6.1.4.1.41482.5.7")
ON_DEVICE = 0x01

class YubiKey(models.Model):
    serial = models.PositiveIntegerField('Serial number', primary_key=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT)

    def __str__(self):
        return str(self.serial)


class PublicKey(models.Model):
    key = models.BinaryField('Public key')


class Attestation(models.Model):
    pubkey = models.OneToOneField(PublicKey, on_delete=models.PROTECT)
    yubikey = models.ForeignKey(YubiKey, on_delete=models.PROTECT)
    intermediate_cert = models.BinaryField('Intermediate attestation certificate')
    leaf_cert = models.BinaryField('Attestation statement / leaf certificate')

    def validate(self):
        cert = x509.load_der_x509_certificate(self.leaf_cert, default_backend())
        # TODO check chain from Yubico cert through intermediate to leaf
        cks, csn = [DERReader(
            cert.extensions.get_extension_for_oid(oid).value.value
            ).read_element(INTEGER).as_integer()
            for oid in [KEY_SOURCE, SERIAL_NO]]
        assert cks == ON_DEVICE
        assert csn == self.yubikey.serial

class CA(models.Model):
    signer = models.OneToOneField(Attestation, on_delete=models.PROTECT)


class Certificate(models.Model):
    issuer = models.ForeignKey(CA, on_delete=models.PROTECT)
    subject = models.ForeignKey(PublicKey, on_delete=models.PROTECT)
    cert = models.BinaryField('Certificate')
