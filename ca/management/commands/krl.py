# -*- encoding: utf-8 -*-

from argparse import FileType
from pathlib import Path
from shutil import rmtree
from subprocess import Popen, check_call
from tempfile import mkdtemp

from django.core.management.base import BaseCommand

from ca.models import CA, PublicKey

class Command(BaseCommand):
    help = 'Creates a Key Revocation List (KRL)'

    def add_arguments(self, parser):
        parser.add_argument('outfile', type=FileType('wb'))

    def handle(self, outfile, *args, **options):
        outfile.write(generate_krl_contents())

def generate_krl_contents():
    ca_krl = None
    for ca in CA.objects.filter(signer__pubkey__revoked=None):
        ca_krl = ca.get_krl(ca_krl)
    keys = [k.ssh_string() for k in PublicKey.objects.exclude(revoked=None)]
    if not keys:
        return ca_krl
    tmpdir = Path(mkdtemp(prefix='zsca-pub-krl'))
    try:
        krl = tmpdir / 'krl'
        cmdline = ['ssh-keygen', '-k', '-f', str(krl)]
        if ca_krl:
            krl.write_bytes(ca_krl)
            cmdline.append('-u')
        for n, k in enumerate(keys):
            entry_file = tmpdir / 'entry{0}'.format(n)
            entry_file.write_text(k)
            cmdline.append(str(entry_file))
        check_call(cmdline)
        return krl.read_bytes()
    finally:
        rmtree(tmpdir)
