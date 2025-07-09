#!/usr/bin/python3
import hashlib
import base64
import requests
import sys
import argparse
import os
import json

ca_file = 'staas-ca.pem'


def sign_image(image, token, comment, bundle_output_file, verbose):
    # 1. Generate payload with cosign
    os.system(f'cosign generate {image} > payload.json')
    print("Generated image payload json ")
    payload_file = 'payload.json'
    with open(payload_file,"rb") as f:
        bytes = f.read() # read entire file as bytes
        artifact_digest = hashlib.sha256(bytes).digest()

    # 2. Send payload's hash to STaaS for signing
    url="https://staas.excid.io/"
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Basic ' + token
    }

    payload = f"""
    {{
        "HashBase64":"{base64.b64encode(artifact_digest).decode()}",
        "Comment":"{comment}"
    }} """

    if verbose:
        print(payload)

    response = requests.request("POST", url + "Api/Sign", headers=headers, data=payload)
    if verbose:
        print(response.text)
    print("Response code: " + str(response.status_code))
    print("Signed image " + image)
    # 3. Save output bundle locally in a file
    with open(bundle_output_file, "w") as text_file:
        text_file.write(response.text)
    print("Wrote bundle to " + bundle_output_file)

    # 4. Attach signature to OCI registry
    with open(bundle_output_file, 'r') as infile:
        data = json.load(infile)
        signature = data.get("base64Signature")
        rekor_bundle = data.get("rekorBundle")
        cert_decoded = base64.b64decode(data.get("cert")).decode('utf-8')
        sig_file = 'image.sig'
        cert_file = 'cert.pem'
        rekor_file = 'rekor.bundle'

    with open(sig_file, 'w') as outfile:
        outfile.write(signature)
    with open(cert_file, 'w') as outfile:
        outfile.write(cert_decoded)
    with open(rekor_file, 'w') as outfile:
        json.dump(rekor_bundle, outfile, indent=4)

    download_ca_pem(ca_file)

    exit_status = os.system(f'cosign attach signature {image} --signature {sig_file} --payload {payload_file} --certificate-chain {ca_file} --certificate {cert_file} --rekor-response {rekor_file}')
    if (exit_status == 0):  # success
        print("Attached signature to image " + image)
    else:
        print("Could not attach signature")
    
    os.remove(sig_file)
    os.remove(cert_file)
    os.remove(rekor_file)

def sign_blob(artifact, token, comment, output, verbose):

    with open(artifact,"rb") as f:
        bytes = f.read() # read entire file as bytes
        artifact_digest = hashlib.sha256(bytes).digest()

    url="https://staas.excid.io/"
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Basic ' + token
    }

    payload = f"""
    {{
        "HashBase64":"{base64.b64encode(artifact_digest).decode()}",
        "Comment":"{comment}"
    }} """

    if verbose:
        print(payload)

    response = requests.request("POST", url + "Api/Sign", headers=headers, data=payload)
    if verbose:
        print(response.text)
    print("Response code: " + str(response.status_code))

    print("Signed artifact " + artifact)
    with open(output, "w") as text_file:
        text_file.write(response.text)
    print("Wrote bundle to " + output)

def download_ca_pem(output_file):
    url = "http://staas.excid.io/Sign/Certificate"
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(output_file, 'wb') as file:
            file.write(response.content)
        print(f'Successfully downloaded {output_file}')
    except requests.exceptions.RequestException as e:
        print(f'Error downloading file: {e}')

def download_cosign():
    url = "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
    try:
        # Send a GET request to the URL
        response = requests.get(url, allow_redirects=True)
        response.raise_for_status()  # Raise an error for bad responses

        output_path = 'cosign'
        with open(output_path, 'wb') as file:
            file.write(response.content)

        print(f'Successfully downloaded {output_path}')
    except requests.exceptions.RequestException as e:
        print(f'Error downloading file: {e}')
    try: 
        os.system("ls -la")
        os.system("mv cosign /usr/bin/cosign")
        os.chmod("/usr/bin/cosign", 0o755)
        print("Cosign installed")
    except Exception as e:
        print(f'Error moving and changing file permissions: {e}')

def main():

    parser = argparse.ArgumentParser(description="Sign an artifact using STaaS (https://staas.excid.io)\nA path to an artifact is provided, and its digest is sent to STaaS. STaaS then returns the signature in a bundle.")
    subparsers = parser.add_subparsers(dest='command')

    sign_image_parser = subparsers.add_parser('sign-image', help='Sign a container image')
    sign_image_parser.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    sign_image_parser.add_argument('-c', '--comment', type=str, metavar='', required=False, default='Signed Image w/ STaaS CLI', help='A comment to accompany the signing (staas-specific info, not related to signature)')
    sign_image_parser.add_argument('-o', '--output', type=str, metavar='', required=False, default='output.bundle', help='Name output file (default is output.bundle)')
    sign_image_parser.add_argument('image', type=str, metavar='', help='Image to sign. Provide full URL to container registry e.g., registry.gitlab.com/some/repository')

    sign_blob_parser = subparsers.add_parser('sign-blob', help='Sign a blob (arbitrary artifact)')
    sign_blob_parser.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    sign_blob_parser.add_argument('-c', '--comment', type=str, metavar='', required=False, default='Signed Blob w/ STaaS CLI', help='A comment to accompany the signing (staas-specific info, not related to signature)')
    sign_blob_parser.add_argument('-o', '--output', type=str, metavar='', required=False, default='output.bundle', help='Name output file (default is output.bundle)')
    sign_blob_parser.add_argument('artifact', type=str, metavar='', help='Path to the artifact to sign')

    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    cosign_exists = os.system("cosign version")
    if cosign_exists != 0:
        download_cosign()

    if args.command == 'sign-image':
        if args.token is None or args.image is None:
            sign_image_parser.print_help()
            sys.exit(1)
        sign_image(args.image, args.token, args.comment, args.output, args.verbose)
    elif args.command == 'sign-blob':
        if not args.artifact:
            sign_blob_parser.print_help()
            sys.exit(1) 
        sign_blob(args.artifact, args.token, args.comment, args.output, args.verbose)
    else:
        parser.print_help()
        exit()

if __name__ == "__main__":
    main()