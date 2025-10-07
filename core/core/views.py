import whois
import hashlib
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


#Hashing Function
def hash_string(request):
    context = {}
    if request.method == 'POST':
        input_string = request.POST.get('input_string', '').strip()
        
        if not input_string:
            context['error'] = 'Please provide a string to hash'
            return render(request, 'index.html', context)
            
        try:
            hash_results = {
                'MD5': hashlib.md5(input_string.encode()).hexdigest(),
                'SHA1': hashlib.sha1(input_string.encode()).hexdigest(),
                'SHA256': hashlib.sha256(input_string.encode()).hexdigest(),
                'SHA3_256': hashlib.sha3_256(input_string.encode()).hexdigest(),
                'BLAKE2s': hashlib.blake2s(input_string.encode()).hexdigest()
            }
            context['hash_results'] = hash_results
            context['input_string'] = input_string
            
        except Exception as e:
            context['error'] = f'Error generating hashes: {str(e)}'
            
    return render(request, 'index.html', context)