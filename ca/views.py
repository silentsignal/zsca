from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect

import OpenPGPpy

from ca.models import Certificate

def process_revocation(request, certs):
    certs.update(revoked=request.POST['reason'])

def process_renewal(request, certs):
    device = OpenPGPpy.OpenPGPcard()
    device.verify_pin(1, request.POST['password'])
    for cert in certs:
        cert.renew(device)

CERT_ACTION_MAP = {'revoke': process_revocation, 'renew': process_renewal}

def certificates(request):
    for k, v in CERT_ACTION_MAP.items():
        if k in request.POST:
            v(request, Certificate.objects.filter(
                pk__in=request.POST.getlist('cert_id')))
            return redirect(request.path)
    return render(request, 'certificates.html',
            {'certificates': Certificate.objects.all()})

def export_certificate(request, pk):
    return HttpResponse(
            get_object_or_404(Certificate, pk=pk).ssh_string().encode('utf-8'),
            content_type='text/plain')
