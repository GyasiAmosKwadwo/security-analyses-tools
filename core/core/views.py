import whois
from django.shortcuts import render


def get_whois_info(request):
    context = {}
    if request.method == 'POST':
        domain_name = request.POST.get('domain_name')
        try:
            w = whois.whois(domain_name)
            context['response'] = w.items()
        except Exception as e:
            context['error'] = str(e)
    return render(request, 'index.html', context)