# -*- encoding: utf-8 -*-

from io import BytesIO

from django.core.management.base import BaseCommand

from ca.models import Attestation, CA, read_ssh_string

SSH_ED25519 = b'ssh-ed25519'

class Command(BaseCommand):
    help = 'Creates a CA'

    def add_arguments(self, parser):
        parser.add_argument('attestation_id', type=int)

    def handle(self, *args, **options):
        att = Attestation.objects.get(pk=options['attestation_id'])
        inner_type = read_ssh_string(BytesIO(att.pubkey.key))
        if inner_type != SSH_ED25519:
            raise ValueError("Only Ed25519 CAs are supported by ZSCA")
        CA.objects.create(signer=att)
