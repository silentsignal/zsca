# -*- encoding: utf-8 -*-

from django.core.management.base import BaseCommand

from ca.models import Certificate, console_openpgp_init

class Command(BaseCommand):
    help = 'Renews a certificate'

    def add_arguments(self, parser):
        parser.add_argument('cert_ids')

    def handle(self, cert_ids, *args, **options):
        device = console_openpgp_init()
        for cert_id in cert_ids.split(','):
            Certificate.objects.get(pk=cert_id).renew(device)
