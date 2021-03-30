from base64 import b64decode
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

from django.conf import settings
from django.db import models

from django.contrib.auth.models import User

# src: https://developers.yubico.com/PGP/Attestation.html
PGP_KEY_SOURCE = x509.ObjectIdentifier("1.3.6.1.4.1.41482.5.2")
PGP_SERIAL_NO  = x509.ObjectIdentifier("1.3.6.1.4.1.41482.5.7")
# src: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
PIV_SERIAL_NO  = x509.ObjectIdentifier("1.3.6.1.4.1.41482.3.7")
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
        for certfile in (Path(__file__).parent / 'attestation-ca-certs').glob('*.pem'):
            root = x509.load_pem_x509_certificate(certfile.read_bytes(), be)
            if root.subject == attn.issuer:
                break
        else:
            raise ValueError('Unknown CA')
        for (issuer, subject) in [(root, attn), (attn, cert)]:
            issuer.public_key().verify(
                    subject.signature,
                    subject.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    subject.signature_hash_algorithm)
        try:
            psn = cert.extensions.get_extension_for_oid(PIV_SERIAL_NO)
        except x509.ExtensionNotFound:
            cks, csn = [DERReader(
                cert.extensions.get_extension_for_oid(oid).value.value
                ).read_element(INTEGER).as_integer()
                for oid in [PGP_KEY_SOURCE, PGP_SERIAL_NO]]
            assert cks == ON_DEVICE
        else:
            csn = DERReader(psn.value.value).read_element(INTEGER).as_integer()
        assert csn == self.yubikey.serial
        ossh_pubkey = b64decode(cert.public_key().public_bytes(
                format=serialization.PublicFormat.OpenSSH,
                encoding=serialization.Encoding.OpenSSH).split(b' ', 1)[-1])
        assert ossh_pubkey == self.pubkey.key

    def verify(self, signature, data):
        cert = x509.load_der_x509_certificate(self.leaf_cert, default_backend())
        cert.public_key().verify(signature['ssh-ed25519'], data)


class CA(models.Model):
    signer = models.OneToOneField(Attestation, on_delete=models.PROTECT)


KEY_PARAMS = {
        "ecdsa-sha2-nistp256": 2,
        "ecdsa-sha2-nistp384": 2,
        "ecdsa-sha2-nistp521": 2,
        "ssh-ed25519": 1,
        "ssh-rsa": 2,
        # DSA is omitted on purpose
        }

CERT_POSTFIX = "-cert-v01@openssh.com"


class Certificate(models.Model):
    issuer = models.ForeignKey(CA, on_delete=models.PROTECT)
    subject = models.ForeignKey(PublicKey, on_delete=models.PROTECT)
    cert = models.BinaryField('Certificate')

    def parse(self):
        bio = BytesIO(self.cert)
        subject_type = read_ssh_string(bio).decode()
        _nonce = read_ssh_string(bio)
        if not subject_type.endswith(CERT_POSTFIX):
            raise ValueError("unsupported cert type: " + repr(subject_type))
        key_type = subject_type[:-len(CERT_POSTFIX)]
        pos1 = bio.tell()
        pk_components = tuple(read_ssh_string(bio)
                for _ in range(KEY_PARAMS[key_type]))
        pos2 = bio.tell()
        pubkey = {"type": key_type, "components": pk_components,
                "bytes": self.cert[pos1:pos2]}
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
        sub = self.subject
        bio = BytesIO(sub.key)
        pk = parsed['pubkey']
        assert read_ssh_string(bio).decode() == pk['type']
        assert bio.read() == pk['bytes']
        max_seconds = settings.CERT_MAX_DAYS * 60 * 60 * 24
        assert parsed['valid_before'] - parsed['valid_after'] < max_seconds
        if hasattr(sub, 'attestation'):
            assert [sub.attestation.yubikey.user.email] == parsed['principals']
        else:
            assert 'force-command' in parsed['crit_opts']


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
