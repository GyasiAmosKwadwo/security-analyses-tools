from typing import Dict, Any
import whois
import hashlib
import requests
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.conf import settings

def get_whois_info(request: HttpRequest) -> HttpResponse:
    """
    Get WHOIS information for a given domain name.
    """
    context: Dict[str, Any] = {}
    if request.method == 'POST':
        domain_name = request.POST.get('domain_name', '').strip()
        if not domain_name:
            context['error'] = 'Please provide a domain name'
            return render(request, 'index.html', context)
        
        try:
            w = whois.whois(domain_name)
            context['response'] = w.items()
        except Exception as e:
            context['error'] = f'WHOIS lookup failed: {str(e)}'
    
    return render(request, 'index.html', context)

def hash_string(request: HttpRequest) -> HttpResponse:
    """
    Generate hash values for input string or file using multiple algorithms.
    """
    context: Dict[str, Any] = {}
    if request.method == 'POST':
        input_string = request.POST.get('input_string', '').strip()
        uploaded_file = request.FILES.get('file')
        given_hash = request.POST.get('given_hash', '').strip()
        hash_type = request.POST.get('hash_type', '').strip().upper()

        if not input_string and not uploaded_file:
            context['error'] = 'Please provide a string or upload a file to hash'
            return render(request, 'index.html', context)

        try:
            hash_algorithms = {
                'MD5': hashlib.md5,
                'SHA1': hashlib.sha1,
                'SHA256': hashlib.sha256,
                'SHA3_256': hashlib.sha3_256,
                'BLAKE2B': hashlib.blake2b
            }

            if input_string:
                hash_results = {
                    name: algo(input_string.encode()).hexdigest()
                    for name, algo in hash_algorithms.items()
                }
                context.update({
                    'hash_results': hash_results,
                    'input_string': input_string
                })

                if given_hash and hash_type in hash_algorithms:
                    calculated_hash = hash_results.get(hash_type)
                    context['hash_match'] = (
                        f'The given {hash_type} hash '
                        f'{"matches" if calculated_hash == given_hash else "does not match"} '
                        'the calculated hash.'
                    )

            elif uploaded_file:
                hash_objects = {
                    name: algo() for name, algo in hash_algorithms.items()
                }

                for chunk in uploaded_file.chunks():
                    for hash_object in hash_objects.values():
                        hash_object.update(chunk)

                hash_results = {
                    name: obj.hexdigest() 
                    for name, obj in hash_objects.items()
                }
                context.update({
                    'hash_results_file': hash_results,
                    'file_name': uploaded_file.name
                })

        except Exception as e:
            context['error'] = f'Error generating hashes: {str(e)}'

    return render(request, 'index.html', context)

def check_url_status(request: HttpRequest) -> HttpResponse:
    """
    Check HTTP status for given URL or list of URLs from file.
    """
    context: Dict[str, Any] = {}
    if request.method == "POST":
        domain = request.POST.get("domain_name", '').strip()
        file = request.FILES.get("file")
        timeout = getattr(settings, 'URL_TIMEOUT', 5)

        if not domain and not file:
            context['error'] = 'Please provide a domain name or upload a file'
            return render(request, 'index.html', context)

        def check_single_url(url: str) -> str:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            try:
                response = requests.get(url, timeout=timeout)
                return f"URL: {url} - Status Code: {response.status_code}"
            except requests.RequestException as e:
                return f"URL: {url} - Error: {str(e)}"

        if domain:
            context['url_status'] = check_single_url(domain)
        elif file:
            url_statuses = []
            for line in file:
                domain = line.decode('utf-8').strip()
                if domain:
                    url_statuses.append(check_single_url(domain))
            context['url_statuses'] = url_statuses

    return render(request, 'index.html', context)