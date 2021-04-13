# -*- encoding: utf-8 -*-

from base64 import b64encode, b64decode
from io import BytesIO
from pathlib import Path
from subprocess import Popen
from tempfile import mkdtemp
import getpass, socket, struct

from django.conf import settings
from django.core.management.base import BaseCommand

import OpenPGPpy

from ca.models import Attestation, CA, PublicKey, read_ssh_string

SSH_ED25519 = b'ssh-ed25519'
SIGNING_KEY = "B600"
SECURITY_SUPPORT_TEMPLATE = '007A'
OPGP_ED25519_PREFIX = b"\x7f\x49\x22\x86\x20"
OPGP_SIG_CTR_PREFIX = b"z\x05\x93\x03"

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14

class Command(BaseCommand):
    help = 'Signs a certificate'

    def add_arguments(self, parser):
        parser.add_argument('pubkey_id', type=int)
        parser.add_argument('--identity')
        parser.add_argument('--principal')
        parser.add_argument('-O', dest='ssh_keygen_options',
                metavar='ssh-keygen_option', action='append')

    def handle(self, identity, principal, ssh_keygen_options, *args, **options):
        subject_pk = PublicKey.objects.get(pk=options['pubkey_id'])
        force_cmd = False
        cmdline_options = []
        for opt in ssh_keygen_options or []:
            cmdline_options.append('-O')
            cmdline_options.append(opt)
            if opt.startswith('force-command='):
                force_cmd = True
        if hasattr(subject_pk, 'attestation'):
            if identity:
                raise ValueError("--identity doesn't make sense for attested keys, would be overwritten")
            if principal:
                raise ValueError("--principal doesn't make sense for attested keys, would be overwritten")
            yk = subject_pk.attestation.yubikey
            email = yk.user.email
            principal = email
            identity = '{0} YK#{1}'.format(email, yk.serial)
        elif not identity:
            raise ValueError('--identity is mandatory for unattested keys')
        elif not principal:
            raise ValueError('--principal is mandatory for unattested keys')
        elif not force_cmd:
            raise ValueError('Unattested keys must have forced command')
        mydevice = OpenPGPpy.OpenPGPcard()
        sigctr_blob = bytes(mydevice.get_data(SECURITY_SUPPORT_TEMPLATE))
        if len(sigctr_blob) != 7 or not sigctr_blob.startswith(OPGP_SIG_CTR_PREFIX):
            raise ValueError('Invalid reply to signature counter request: ' +
                    repr(sigctr_blob))
        (counter,) = struct.unpack(">I", b"\0" + sigctr_blob[len(OPGP_SIG_CTR_PREFIX):])
        mydevice.verify_pin(1, getpass.getpass())
        pk = mydevice.get_public_key(SIGNING_KEY)
        if len(pk) != 37 or not pk.startswith(OPGP_ED25519_PREFIX):
            raise ValueError('Only Ed25519 keys are supported')
        ed25519bytes = pk[len(OPGP_ED25519_PREFIX):]
        ssh_bytes = b''.join((
            struct.pack('>I', len(SSH_ED25519)),
            SSH_ED25519,
            struct.pack('>I', len(ed25519bytes)),
            ed25519bytes,
            ))
        ca = CA.objects.get(signer__pubkey__key=ssh_bytes)
        tmpdir = Path(mkdtemp(prefix='zsca-signcert'))
        tmpfiles = {}
        for name, source in [('issuer', ca.signer.pubkey), ('subject', subject_pk)]:
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
                response = b''.join((
                        bytes([SSH_AGENT_IDENTITIES_ANSWER]),
                        struct.pack('>I', 1),
                        struct.pack('>I', len(ssh_bytes)),
                        ssh_bytes,
                        struct.pack('>I', 0), # no comment
                        ))
                connection.sendall(struct.pack('>I', len(response)) + response)
            elif cmd == SSH_AGENTC_SIGN_REQUEST:
                (keylen,) = struct.unpack('>I', msg[1:5])
                (datalen,) = struct.unpack('>I', msg[(1+4+keylen):][:4])
                data = msg[(1+4+keylen+4):][:datalen]
                assert 1 + 4 + datalen + 4 + keylen + 4 == len(msg)
                ed25519sig = mydevice.sign(data)
                signature = b''.join((
                    struct.pack('>I', len(SSH_ED25519)),
                    SSH_ED25519,
                    struct.pack('>I', len(ed25519sig)),
                    ed25519sig,
                    ))
                response = b''.join((
                        bytes([SSH_AGENT_SIGN_RESPONSE]),
                        struct.pack('>I', len(signature)),
                        signature,
                        ))
                connection.sendall(struct.pack('>I', len(response)) + response)
            else:
                raise ValueError('Unsupported command {0}'.format(cmd))
        cert = b64decode((tmpdir / 'subject-cert.pub').read_bytes().split(b" ")[1])
        ca.certificate_set.create(subject=subject_pk, cert=cert).validate()
