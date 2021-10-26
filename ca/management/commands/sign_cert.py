# -*- encoding: utf-8 -*-

from django.core.management.base import BaseCommand

from ca.models import PublicKey

class Command(BaseCommand):
    help = 'Signs a certificate'

    def add_arguments(self, parser):
        parser.add_argument('pubkey_id', type=int)
        parser.add_argument('--identity')
        parser.add_argument('--principal')
        parser.add_argument('-O', dest='ssh_keygen_options',
                metavar='ssh-keygen_option', action='append')

    def handle(self, pubkey_id, identity, principal, ssh_keygen_options, *args, **options):
        signed = PublicKey.objects.get(pk=pubkey_id).sign_with_ca(
                identity, principal, ssh_keygen_options)
        print(signed.ssh_string())
