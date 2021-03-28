from functools import partial
from io import BytesIO
from itertools import islice
from pathlib import Path
import struct

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
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
        be = default_backend()
        cert, attn = (x509.load_der_x509_certificate(der, be) for
                der in [self.leaf_cert, self.intermediate_cert])
        # src: https://developers.yubico.com/PGP/opgp-attestation-ca.pem
        root_ca_path = (Path(__file__).parent / 'opgp-attestation-ca.pem')
        root = x509.load_pem_x509_certificate(root_ca_path.read_bytes(), be)
        for (issuer, subject) in [(root, attn), (attn, cert)]:
            issuer.public_key().verify(
                    subject.signature,
                    subject.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    subject.signature_hash_algorithm)
        cks, csn = [DERReader(
            cert.extensions.get_extension_for_oid(oid).value.value
            ).read_element(INTEGER).as_integer()
            for oid in [KEY_SOURCE, SERIAL_NO]]
        assert cks == ON_DEVICE
        assert csn == self.yubikey.serial

    def verify(self, signature, data):
        cert = x509.load_der_x509_certificate(self.leaf_cert, default_backend())
        cert.public_key().verify(signature['ssh-ed25519'], data)


class CA(models.Model):
    signer = models.OneToOneField(Attestation, on_delete=models.PROTECT)


class Certificate(models.Model):
    issuer = models.ForeignKey(CA, on_delete=models.PROTECT)
    subject = models.ForeignKey(PublicKey, on_delete=models.PROTECT)
    cert = models.BinaryField('Certificate')

    def parse(self):
        bio = BytesIO(self.cert)
        subject_type = read_ssh_string(bio).decode()
        _nonce = read_ssh_string(bio)
        if subject_type.startswith('ecdsa'):
            curve = read_ssh_string(bio).decode()
            pubkey = read_ssh_string(bio)
            pubkey = {"curve": curve, "pubkey": pubkey}
        else:
            raise NotImplementedError()
        serial = read_struct(bio, '>Q')
        cert_type = read_struct(bio, '>I')
        key_id = read_ssh_string(bio).decode()
        principals = [p.decode() for p in read_ssh_string_list(bio)]
        valid_after = read_struct(bio, '>Q')
        valid_before = read_struct(bio, '>Q')
        crit_opts =  read_dict(bio)
        extensions = read_dict(bio)
        reserved = read_ssh_string(bio)
        signature_key = read_ssh_string(bio)
        pos = bio.tell()
        signature = read_dict(bio)
        assert bio.read() == b'' # we're at the end
        tbs = self.cert[:pos]
        return {"subject_type": subject_type, "pubkey": pubkey,
                "serial": serial, "cert_type": cert_type, "key_id": key_id,
                "principals": principals, "crit_opts": crit_opts,
                "valid_after": valid_after, "valid_before": valid_before,
                "extensions": extensions, "reserved": reserved, "tbs": tbs,
                "signature_key": signature_key, "signature": signature}

    def validate(self):
        parsed = self.parse()
        isigner = self.issuer.signer
        assert parsed['signature_key'] == isigner.pubkey.key
        isigner.verify(parsed['signature'], parsed['tbs'])
        # TODO check subject pubkey match
        # TODO check expiration date
        # TODO check serial
        # TODO check identity
        # TODO check limitations


def read_dict(bio):
    return {k.decode(): v for k, v in chunked(read_ssh_string_list(bio), 2)}

def read_ssh_string_list(bio):
    container = read_ssh_string(bio)
    return list(iter(partial(try_read_ssh_string, BytesIO(container)), None))

def try_read_ssh_string(bio):
    try:
        return bio.read(read_struct(bio, '>I'))
    except struct.error:
        return None

def read_ssh_string(bio):
    return bio.read(read_struct(bio, '>I'))

def read_struct(bio, fmt):
    (value,) = struct.unpack(fmt, bio.read(struct.calcsize(fmt)))
    return value

# src: https://github.com/more-itertools/more-itertools, license: MIT
def chunked(iterable, n):
	iterator = iter(partial(take, n, iter(iterable)), [])
	for chunk in iterator:
		if len(chunk) != n:
			raise ValueError('iterable is not divisible by n.')
		yield chunk

def take(n, iterable):
    return list(islice(iterable, n))
