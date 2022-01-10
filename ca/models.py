from base64 import b64decode, b64encode
from datetime import datetime
from functools import partial
from hashlib import sha256
from io import BytesIO
from itertools import islice
from pathlib import Path
from shutil import rmtree
from subprocess import Popen, check_call
from tempfile import mkdtemp
from time import time
import getpass, socket, struct

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat._der import DERReader, INTEGER
import OpenPGPpy

from django.conf import settings
from django.db import models

from django.contrib.auth.models import User

# src: https://developers.yubico.com/PGP/Attestation.html
PGP_KEY_SOURCE = x509.ObjectIdentifier("1.3.6.1.4.1.41482.5.2")
PGP_SERIAL_NO  = x509.ObjectIdentifier("1.3.6.1.4.1.41482.5.7")
# src: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
PIV_SERIAL_NO  = x509.ObjectIdentifier("1.3.6.1.4.1.41482.3.7")
ON_DEVICE = 0x01

SSH_ED25519 = b'ssh-ed25519'
SIGNING_KEY = "B600"
SECURITY_SUPPORT_TEMPLATE = '007A'
OPGP_ED25519_PREFIX = b"\x7f\x49\x22\x86\x20"
OPGP_SIG_CTR_PREFIX = b"z\x05\x93\x03"

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14

class YubiKey(models.Model):
    serial = models.PositiveIntegerField('Serial number', primary_key=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT)

    def __str__(self):
        return str(self.serial)


class PublicKey(models.Model):
    key = models.BinaryField('Public key')
    revoked = models.CharField('Reason for revocation', max_length=100, null=True)

    def ssh_string(self):
        return format_ssh_key(self.key)

    def __str__(self):
        h = b64encode(sha256(self.key).digest()).decode()
        return 'SHA256:{0}...{1}'.format(h[:3], h[-3:])

    def sign_with_ca(self, identity, principal, ssh_keygen_options,
            device=None, renewal_of=None):
        force_cmd = False
        cmdline_options = []
        for opt in ssh_keygen_options or []:
            cmdline_options.append('-O')
            cmdline_options.append(opt)
            if opt.startswith('force-command='):
                force_cmd = True
        if hasattr(self, 'attestation'):
            if identity:
                raise ValueError("identity doesn't make sense for attested keys, would be overwritten")
            if principal:
                raise ValueError("principal doesn't make sense for attested keys, would be overwritten")
            yk = self.attestation.yubikey
            email = yk.user.email
            principal = email
            identity = '{0} YK#{1}'.format(email, yk.serial)
        elif not identity:
            raise ValueError('identity is mandatory for unattested keys')
        elif not principal:
            raise ValueError('principal is mandatory for unattested keys')
        elif not force_cmd:
            raise ValueError('Unattested keys must have forced command')
        mydevice = device or console_openpgp_init()
        sigctr_blob = bytes(mydevice.get_data(SECURITY_SUPPORT_TEMPLATE))
        if len(sigctr_blob) != 7 or not sigctr_blob.startswith(OPGP_SIG_CTR_PREFIX):
            raise ValueError('Invalid reply to signature counter request: ' +
                    repr(sigctr_blob))
        (counter,) = struct.unpack(">I", b"\0" + sigctr_blob[len(OPGP_SIG_CTR_PREFIX):])
        pk = mydevice.get_public_key(SIGNING_KEY)
        if len(pk) != 37 or not pk.startswith(OPGP_ED25519_PREFIX):
            raise ValueError('Only Ed25519 keys are supported')
        ed25519bytes = pk[len(OPGP_ED25519_PREFIX):]
        ssh_bytes = serialize_openssh(SSH_ED25519, ed25519bytes)
        ca = CA.objects.get(signer__pubkey__key=ssh_bytes)
        tmpdir = Path(mkdtemp(prefix='zsca-signcert'))
        try:
            tmpfiles = {}
            for name, source in [('issuer', ca.signer.pubkey), ('subject', self)]:
                tmpfile = tmpdir / (name + '.pub')
                tmpfile.write_text(source.ssh_string())
                tmpfiles[name] = tmpfile
            ssh_auth_sock = str(tmpdir / 'ssh.sock')
            env = {'SSH_AUTH_SOCK': ssh_auth_sock}
            cmdline = ['ssh-keygen', '-Us', str(tmpfiles['issuer']),
                '-V', '+{0}d'.format(settings.CERT_MAX_DAYS), '-z', str(counter),
                '-I', identity, '-n', principal] + cmdline_options
            cmdline.append(str(tmpfiles['subject']))
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(ssh_auth_sock)
            sock.listen(1)
            keygen = Popen(cmdline, env=env)
            connection, client_address = sock.accept()
            while keygen.poll() is None:
                msglen = connection.recv(4)
                if not msglen:
                    continue
                msg = connection.recv(struct.unpack('>I', msglen)[0])
                cmd = msg[0]
                if cmd == SSH_AGENTC_REQUEST_IDENTITIES:
                    response = serialize_openssh([(ssh_bytes, b'')],
                            prefix=SSH_AGENT_IDENTITIES_ANSWER)
                    connection.sendall(struct.pack('>I', len(response)) + response)
                elif cmd == SSH_AGENTC_SIGN_REQUEST:
                    (keylen,) = struct.unpack('>I', msg[1:5])
                    (datalen,) = struct.unpack('>I', msg[(1+4+keylen):][:4])
                    data = msg[(1+4+keylen+4):][:datalen]
                    assert 1 + 4 + datalen + 4 + keylen + 4 == len(msg)
                    ed25519sig = mydevice.sign(data)
                    signature = serialize_openssh(SSH_ED25519, ed25519sig)
                    response = serialize_openssh(signature, prefix=SSH_AGENT_SIGN_RESPONSE)
                    connection.sendall(struct.pack('>I', len(response)) + response)
                else:
                    raise ValueError('Unsupported command {0}'.format(cmd))
            cert = b64decode((tmpdir / 'subject-cert.pub').read_bytes().split(b" ")[1])
        finally:
            rmtree(tmpdir)
        signed = ca.certificate_set.create(subject=self, cert=cert,
                renewal_of=renewal_of)
        signed.validate()
        return signed

def console_openpgp_init():
    mydevice = OpenPGPpy.OpenPGPcard()
    mydevice.verify_pin(1, getpass.getpass())
    return mydevice

def serialize_openssh(*args, prefix=None):
    payload = b''.join(serialize_openssh_value(arg) for arg in args)
    return payload if prefix is None else bytes([prefix]) + payload

def serialize_openssh_value(value):
    if isinstance(value, list):
        return serialize_openssh(len(value), *value)
    if isinstance(value, tuple):
        return serialize_openssh(*value)
    elif isinstance(value, int):
        return struct.pack('>I', value)
    elif isinstance(value, bytes):
        return serialize_openssh_value(len(value)) + value


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
        csn = read_yubikey_serial(cert)
        assert csn == self.yubikey.serial, (
                "serial attested by {0!r} ({1!r}) doesn't match YubiKey {2!r}".format(
                    self, csn, self.yubikey))
        ossh_pubkey = b64decode(cert.public_key().public_bytes(
                format=serialization.PublicFormat.OpenSSH,
                encoding=serialization.Encoding.OpenSSH).split(b' ', 1)[-1])
        assert ossh_pubkey == self.pubkey.key, (("public key attested by {0!r} "
            "doesn't match linked public key {1!r}").format(self, self.pubkey))

    def verify(self, signature, data):
        cert = x509.load_der_x509_certificate(self.leaf_cert, default_backend())
        cert.public_key().verify(signature['ssh-ed25519'], data)


def read_yubikey_serial(cert):
    try:
        psn = cert.extensions.get_extension_for_oid(PIV_SERIAL_NO)
    except x509.ExtensionNotFound:
        cks, csn = [DERReader(
            cert.extensions.get_extension_for_oid(oid).value.value
            ).read_element(INTEGER).as_integer()
            for oid in [PGP_KEY_SOURCE, PGP_SERIAL_NO]]
        assert cks == ON_DEVICE, repr(self) + " was imported into the YubiKey"
    else:
        csn = DERReader(psn.value.value).read_element(INTEGER).as_integer()
    return csn


class CA(models.Model):
    signer = models.OneToOneField(Attestation, on_delete=models.PROTECT)

    def validate(self):
        self.signer.validate()
        certs = []
        for cert in self.certificate_set.all():
            cert.validate()
            certs.append(cert.cert)
        assert len(set(certs)) == len(certs), (
                "not all certificates signed by {0!r} are unique".format(self))

    def get_krl(self, update=None):
        entries = list(self.get_revocation_entries())
        if not entries:
            return update
        tmpdir = Path(mkdtemp(prefix='zsca-cert-krl'))
        try:
            krl = tmpdir / 'krl'
            cmdline = ['ssh-keygen', '-k', '-f', str(krl)]
            if update:
                krl.write_bytes(update)
                cmdline.append('-u')
            entry_file = tmpdir / 'entries'
            entry_file.write_text('\n'.join(entries))
            ca = tmpdir / 'ca'
            ca.write_text(self.signer.pubkey.ssh_string())
            check_call(cmdline + ['-s', str(ca), str(entry_file)])
            return krl.read_bytes()
        finally:
            rmtree(tmpdir)

    def get_revocation_entries(self):
        t = time()
        for cert in self.certificate_set.exclude(revoked=None):
            pc = cert.parse()
            if t > pc['valid_before']:
                continue # wouldn't be valid anyway
            yield 'serial: ' + str(pc['serial'])


KEY_PARAMS = {
        "ecdsa-sha2-nistp256": 2,
        "ecdsa-sha2-nistp384": 2,
        "ecdsa-sha2-nistp521": 2,
        "ssh-ed25519": 1,
        "ssh-rsa": 2,
        # DSA is omitted on purpose
        }

CERT_POSTFIX = "-cert-v01@openssh.com"
FORCE_COMMAND = 'force-command'
VERIFY_REQUIRED = 'verify-required'
SOURCE_ADDRESS = 'source-address'
NO_TOUCH_REQUIRED = 'no-touch-required'
SSH_PERMISSIONS = ['X11-forwarding', 'agent-forwarding', 'port-forwarding', 'pty', 'user-rc']


class Certificate(models.Model):
    issuer = models.ForeignKey(CA, on_delete=models.PROTECT)
    subject = models.ForeignKey(PublicKey, on_delete=models.PROTECT)
    cert = models.BinaryField('Certificate')
    renewal_of = models.ForeignKey('self', null=True, on_delete=models.PROTECT)
    revoked = models.CharField('Reason for revocation', max_length=100, null=True)

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
        valid_after  = read_struct(bio, '>Q')
        valid_before = read_struct(bio, '>Q')
        crit_opts  = read_dict(bio)
        extensions = read_dict(bio)
        reserved = read_ssh_string(bio)
        signature_key = read_ssh_string(bio)
        pos = bio.tell()
        signature = read_dict(bio)
        assert bio.read() == b'', repr(self) + " has trailing bytes"
        tbs = self.cert[:pos]
        return {"subject_type": subject_type, "pubkey": pubkey,
                "serial": serial, "cert_type": cert_type, "key_id": key_id,
                "principals": principals, "crit_opts": crit_opts,
                "valid_after": valid_after, "valid_before": valid_before,
                "extensions": extensions, "reserved": reserved, "tbs": tbs,
                "signature_key": signature_key, "signature": signature,
                }

    def status(self):
        if self.revoked:
            return f'Certificate revoked: {self.revoked}'
        if self.subject.revoked:
            return f'Key revoked: {self.subject.revoked}'
        t = time()
        p = self.parse()
        if p["valid_after"] > t:
            return f'Not yet valid, will be from {datetime.fromtimestamp(p["valid_after"])}'
        vb = p["valid_before"]
        expiration = datetime.fromtimestamp(vb)
        if vb < t:
            return f'Expired at {expiration}'
        r = self.issuer.signer.pubkey.revoked
        if r:
            return f'CA revoked: {r}'
        return f'Valid until {expiration} ({int((vb-t)//3600//24)} day(s))'

    def renew(self, device=None):
        cert = self.parse()
        pk = self.subject
        if hasattr(pk, 'attestation'):
            identity = principal = None
        else:
            identity = cert['key_id']
            principal = ','.join(cert['principals'])
        pk.sign_with_ca(identity, principal, ssh_keygen_options(cert), device, self)

    def validate(self):
        parsed = self.parse()
        isigner = self.issuer.signer
        assert parsed['signature_key'] == isigner.pubkey.key, (
                "{0!r} contains a different issuer key, not {1!r}".format(self, isigner))
        isigner.verify(parsed['signature'], parsed['tbs'])
        sub = self.subject
        bio = BytesIO(sub.key)
        pk = parsed['pubkey']
        assert read_ssh_string(bio).decode() == pk['type'], (
                "{0!r} has a different keytype than {1!r}".format(self, sub))
        assert bio.read() == pk['bytes'], (
                "{0!r} has a different key than {1!r}".format(self,sub))
        max_seconds = settings.CERT_MAX_DAYS * 60 * 60 * 24 + 120 # +2 minutes
        valid_seconds = parsed['valid_before'] - parsed['valid_after']
        assert valid_seconds < max_seconds, repr(self) + " is valid for too long"
        if hasattr(sub, 'attestation'):
            att = sub.attestation
            att.validate()
            pp = parsed['principals']
            email = att.yubikey.user.email
            assert [email] == pp, (
                    "{0!r} has incorrect principals: {1!r}".format(self, pp))
            kid = parsed['key_id']
            assert email in kid, (("{0!r} doesn't contain the email address {1!r} "
                "in the key_id {2!r}").format(self, email, kid))
            serial = att.yubikey.serial
            assert str(serial) in kid, (("{0!r} doesn't contain the YubiKey "
                "serial ({1}) in the key_id {2!r}").format(self, serial, kid))
        else:
            assert 'force-command' in parsed['crit_opts'], (
                    repr(self) + " had no force-command option set")

    def ssh_string(self):
        return format_ssh_key(self.cert)

    def __str__(self):
        parsed = self.parse()
        return "{0} signed by {1}, serial {2}".format(self.subject,
                self.issuer.signer.pubkey, parsed['serial'])

def ssh_keygen_options(cert):
    crit_opts = cert['crit_opts']
    for key in [FORCE_COMMAND, SOURCE_ADDRESS]:
        value = crit_opts.get(key)
        if value:
            yield '='.join((key, read_ssh_string(BytesIO(value)).decode()))
    if VERIFY_REQUIRED in crit_opts:
        yield VERIFY_REQUIRED

    extensions = cert['extensions']
    for perm in SSH_PERMISSIONS:
        if 'permit-' + perm not in extensions:
            yield 'no-' + perm.lower() # X11 -> x11
    if NO_TOUCH_REQUIRED in extensions:
        yield NO_TOUCH_REQUIRED

def format_ssh_key(serialized):
    return b" ".join([
        read_ssh_string(BytesIO(serialized)),
        b64encode(serialized)
        ]).decode()

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
