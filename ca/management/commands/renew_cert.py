# -*- encoding: utf-8 -*-

from django.core.management.base import BaseCommand

from ca.models import Certificate

class Command(BaseCommand):
    help = 'Renews a certificate'

    def add_arguments(self, parser):
        parser.add_argument('cert_id', type=int)

    def handle(self, cert_id, *args, **options):
        Certificate.objects.get(pk=cert_id).renew()
