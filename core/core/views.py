import whois
import hashlib
from django.shortcuts import render
from django.core.files.uploadedfile import UploadedFile


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
        uploaded_file = request.FILES.get('file')
        given_hash = request.POST.get('given_hash', '').strip()
        hash_type = request.POST.get('hash_type', '').strip()

        if not input_string and not uploaded_file:
            context['error'] = 'Please provide a string or upload a file to hash'
            return render(request, 'index.html', context)

        try:
            if input_string:
                hash_results = {
                    'MD5': hashlib.md5(input_string.encode()).hexdigest(),
                    'SHA1': hashlib.sha1(input_string.encode()).hexdigest(),
                    'SHA256': hashlib.sha256(input_string.encode()).hexdigest(),
                    'SHA3_256': hashlib.sha3_256(input_string.encode()).hexdigest(),
                    'BLAKE2s': hashlib.blake2s(input_string.encode()).hexdigest()
                }
                context['hash_results'] = hash_results
                context['input_string'] = input_string

                if given_hash and hash_type:
                    calculated_hash = hash_results.get(hash_type.upper())
                    if calculated_hash == given_hash:
                        context['hash_match'] = f'The given {hash_type} hash matches the calculated hash.'
                    else:
                        context['hash_match'] = f'The given {hash_type} hash does not match the calculated hash.'

            elif uploaded_file:
                hash_results_file = {
                    'MD5': hashlib.md5(),
                    'SHA1': hashlib.sha1(),
                    'SHA256': hashlib.sha256(),
                    'SHA3_256': hashlib.sha3_256(),
                    'BLAKE2s': hashlib.blake2s()
                }

                for chunk in uploaded_file.chunks():
                    for hash_object in hash_results_file.values():
                        hash_object.update(chunk)

                hash_results_file = {k: v.hexdigest() for k, v in hash_results_file.items()}
                context['hash_results_file'] = hash_results_file
                context['file_name'] = uploaded_file.name

                if given_hash and hash_type:
                    calculated_hash = hash_results_file.get(hash_type.upper())
                    if calculated_hash == given_hash:
                        context['hash_match_file'] = f'The given {hash_type} hash matches the calculated hash for the file.'
                    else:
                        context['hash_match_file'] = f'The given {hash_type} hash does not match the calculated hash for the file.'

        except Exception as e:
            context['error'] = f'Error generating hashes: {str(e)}'

    return render(request, 'index.html', context)
