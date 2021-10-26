# -*- encoding: utf-8 -*-

from django.core.management.base import BaseCommand

from ca.models import CA

class Command(BaseCommand):
    help = 'Prints the trusted CA list'

    def handle(self, *args, **options):
        for ca in CA.objects.filter(signer__pubkey__revoked=None):
            print(ca.signer.pubkey.ssh_string())
