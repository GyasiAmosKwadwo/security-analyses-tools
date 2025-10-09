from typing import Dict, Any
import whois
import hashlib
import requests
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from typing import Dict, Any
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
import os


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




API_KEY = os.getenv('VT_API_KEY')

def get_vt_headers():
    return {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

def domain_report(domain):
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = requests.get(url, headers=get_vt_headers())
    return response.json()

def ip_address_report(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=get_vt_headers())
    return response.json()

def file_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=get_vt_headers())
    return response.json()


def check_url_status(request: HttpRequest) -> HttpResponse:
    """
    Analyze URLs and files using VirusTotal API
    """
    context: Dict[str, Any] = {}
    if request.method == "POST":
        domain = request.POST.get("domain_name", '').strip()
        file = request.FILES.get("file")

        if not domain and not file:
            context['error'] = 'Please provide a URL or upload a file'
            return render(request, 'index.html', context)

        # Domain analysis
        if domain:
            try:
                vt_domain = domain_report(domain)
                if 'data' in vt_domain:
                    attributes = vt_domain['data']['attributes']
                    stats = attributes.get('last_analysis_stats', {})
                    
                    # Calculate detection ratio and status
                    total_scans = sum(stats.values())
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    threat_score = (malicious + suspicious) / total_scans if total_scans > 0 else 0
                    
                    status = 'Clean'
                    if threat_score > 0.5:
                        status = 'Malicious'
                    elif threat_score > 0.2:
                        status = 'Suspicious'

                    context['domain_info'] = {
                        'name': domain,
                        'categories': attributes.get('categories', {}),
                        'creation_date': attributes.get('creation_date', 'N/A'),
                        'last_analysis_stats': stats,
                        'reputation': attributes.get('reputation', 0),
                        'registrar': attributes.get('registrar', 'N/A'),
                        'status': status,
                        'community_score': threat_score * 100,  # Convert to percentage
                        'server': attributes.get('last_https_certificate', {}).get('issuer', {}).get('O', 'N/A'),
                        'content_type': attributes.get('last_http_response_content_type', 'N/A'),
                        'total_votes': attributes.get('total_votes', {}),
                    }
            except Exception as e:
                context['domain_error'] = f'Domain analysis error: {str(e)}'

        # File analysis
        if file:
            try:
                # Calculate file hashes
                md5 = hashlib.md5()
                sha1 = hashlib.sha1()
                sha256 = hashlib.sha256()

                for chunk in file.chunks():
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)

                file_hashes = {
                    'md5': md5.hexdigest(),
                    'sha1': sha1.hexdigest(),
                    'sha256': sha256.hexdigest()
                }

                # Get file report from VirusTotal
                vt_file = file_report(file_hashes['sha256'])
                
                if 'data' in vt_file:
                    attributes = vt_file['data']['attributes']
                    stats = attributes.get('last_analysis_stats', {})
                    
                    # Calculate detection ratio and status
                    total_scans = sum(stats.values())
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    threat_score = (malicious + suspicious) / total_scans if total_scans > 0 else 0
                    
                    status = 'Clean'
                    if threat_score > 0.5:
                        status = 'Malicious'
                    elif threat_score > 0.2:
                        status = 'Suspicious'

                    context['file_info'] = {
                        'name': file.name,
                        'size': file.size,
                        'type': attributes.get('type_description', 'Unknown'),
                        'magic': attributes.get('magic', 'N/A'),
                        'hashes': file_hashes,
                        'first_seen': attributes.get('first_submission_date', 'N/A'),
                        'last_seen': attributes.get('last_submission_date', 'N/A'),
                        'times_submitted': attributes.get('times_submitted', 0),
                        'last_analysis_stats': stats,
                        'status': status,
                        'community_score': threat_score * 100,  # Convert to percentage
                        'total_votes': attributes.get('total_votes', {}),
                        'signatures': attributes.get('signatures', []),
                        'sandbox_verdicts': attributes.get('sandbox_verdicts', {}),
                        'type_tags': attributes.get('type_tags', []),
                        'names': attributes.get('names', [])[:5]  # Show first 5 names seen
                    }

            except Exception as e:
                context['file_error'] = f'File analysis error: {str(e)}'
    print(context)
    return render(request, 'index.html', context)