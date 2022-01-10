# -*- encoding: utf-8 -*-

from base64 import b64decode
from io import BytesIO

from django.core.management.base import BaseCommand

from ca.models import PublicKey

class Command(BaseCommand):
    help = 'Fetches the latest certificate for a given Base64-encoded public key'

    def add_arguments(self, parser):
        parser.add_argument('pubkey')

    def handle(self, pubkey, *args, **options):
        pk = PublicKey.objects.get(key=b64decode(pubkey))
        lc = pk.certificate_set.order_by('pk').last()
        if lc:
            print(f'command="echo {lc.ssh_string()}",restrict {pk.ssh_string()}')
