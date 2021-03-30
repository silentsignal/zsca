# -*- encoding: utf-8 -*-

from django.core.management.base import BaseCommand

from ca.models import CA

class Command(BaseCommand):
    help = 'Validates every certificate and attestation'

    def handle(self, *args, **options):
        for ca in CA.objects.all():
            ca.validate()
