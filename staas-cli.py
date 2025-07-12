#!/usr/bin/python3
import hashlib
import base64
import argparse
import os
import json
import sys
import requests

# global vars
ca_file = 'staas-ca.pem'
cosign_executable = ""

def sign_image(image, token, comment, bundle_output_file, upload, verbose):
    # 1. Generate payload with cosign
    os.system(f'{cosign_executable} generate {image} > payload.json')
    print("Generated image payload json ")
    payload_file = 'payload.json'
    # 2. Sign image with STaaS
    sign_blob(payload_file, token, comment, bundle_output_file, verbose)

    # 3. Attach signature to OCI registry
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

    if upload == True:
        exit_status = os.system(f'{cosign_executable} attach signature {image} --signature {sig_file} --payload {payload_file} --certificate-chain {ca_file} --certificate {cert_file} --rekor-response {rekor_file}')
        if (exit_status == 0):  # success
            print("Attached signature to image " + image)
        else:
            print("Could not attach signature")
    else: 
        print("Upload option set to \"False\", skipping uploading")

    os.remove(payload_file)
    os.remove(sig_file)
    os.remove(cert_file)
    os.remove(rekor_file)
    os.remove(ca_file)

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

def attest(image, predicate, predicate_type, token, comment, att_output_file, bundle_output_file, upload, verbose):
    # 1. Craft in-toto statement using predicate_type and predicate
    command = "docker buildx imagetools inspect " + image + " | awk '/Digest:/{split($2,a,\":\"); print a[2]}'"
    # 1.a Get digest of provided image
    try:
        with os.popen(command, 'r') as pipe:
            output_string = pipe.read()
            status = pipe.close()

        if status is not None and status != 0:
            print(f"Command failed with exit status {status}")
            print(f"Command Output (potential error messages):\n{output_string}")
            digest = None
        else:
            digest = output_string.strip()
            if not digest: # Check if the output was empty after stripping
                print("Command executed successfully but returned no digest.")
                digest = None
    except Exception as e:
        print(f"An error occurred while running the command, and could not fetch the digest: {e}")
        digest = None
        return

    if digest:
        print(f"The digest of the image is: {digest}")
    else:
        print("Failed to obtain the digest.")
        return

    # 1.b Predicate is stored in a file, so we need to read it an store it inside the json field.
    intoto_statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": predicate_type,
        "subject": [{
            "name": image.split(':')[0],
            "digest": {
                "sha256": digest
            }
        }],
        "predicate": "<PREDICATE>"
    }
    with open(predicate, 'r') as predicate_file:
        predicate_data = json.load(predicate_file)
    
    intoto_statement["predicate"] = predicate_data

    with open('intoto.json', 'w') as intoto_file:
        json.dump(intoto_statement, intoto_file, indent=4)
    print("Created in-toto statement")

    if (verbose):
        print(intoto_statement)

    # 2. Sign in-toto statement using STaaS
    sign_blob('intoto.json', token, comment, bundle_output_file, verbose)

    # 3. Craft DSSE envelope
    dsse = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": "<Base64(INTOTO-STATEMENT)>",
        "signatures": [{
            "sig": "<Base64(SIGNATURE)>"
        }]
    }
    # 3.a Set the payload
    payload_base64 = base64.b64encode(json.dumps(intoto_statement).encode('utf-8')).decode('utf-8')
    dsse["payload"] = payload_base64
    os.remove('intoto.json') # no need for the file anymore
    # 3.b Set the signature (stored in intoto.json.bundle)
    with open(bundle_output_file, 'r') as bundle_file:
        bundle_data = json.load(bundle_file)
        signature = bundle_data["base64Signature"]
    dsse['signatures'][0]['sig'] = signature

    # 4. Dump DSSE into a file
    with open(att_output_file, 'w') as attestation_file:
        json.dump(dsse, attestation_file, indent=4)
    print("Created DSSE envelope")

    # 5. Create manifest annotations and then attach to the image
    if upload == False:
        print("Upload option set to \"False\", skipping uploading")
        return

    annotations = {
        att_output_file : {
            "dev.sigstore.cosign/bundle": "",
            "dev.sigstore.cosign/certificate": "",
            "dev.sigstore.cosign/chain": "",
            "predicateType": ""
        }
    }

    annotations[att_output_file]["predicateType"] = intoto_statement["predicateType"]
    annotations[att_output_file]["dev.sigstore.cosign/bundle"] = json.dumps(bundle_data["rekorBundle"])
    cert = base64.b64decode(bundle_data.get("cert")).decode('utf-8')
    annotations[att_output_file]["dev.sigstore.cosign/certificate"] = cert
    download_ca_pem(ca_file)
    with open(ca_file, 'r') as ca:
        ca_data = ca.read()
    annotations[att_output_file]["dev.sigstore.cosign/chain"] = ca_data

    annotations_file = 'annotations.json'
    with open(annotations_file, 'w') as ann_file:
        json.dump(annotations, ann_file, indent=4)
    print("Created annotations")

    # 6. Attach

    registry = image.split('/')[0]
    image_ref = image.split(':')[0]

    os.system(f"oras tag {image} {image_ref}:sha256-{digest}.att")
    os.system(f"oras push {image_ref}:sha256-{digest}.att --artifact-type application/vnd.oci.image.manifest.v1+json {att_output_file}:application/vnd.dsse.envelope.v1+json --annotation-file {annotations_file}")
    # exit_status = os.system(f"{cosign_executable} attach attestation --attestation {att_output_file} {image}")
    # if (exit_status == 0):  # success
    #     print("Attached attstation to image " + image)
    # else:
    #     print("Could not attach signature")
    os.remove(ca_file)

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
    global cosign_executable
    print("Cosign not found in PATH, proceeding to download it")
    if os.name == 'nt':
        print("OS detected: Windows\nDownloading cosign for Windows")
        url = "https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe"
        output_path = 'cosign.exe'
        cosign_executable = ".\\cosign.exe"
    elif os.name == 'posix':
        print("OS detected: Linux\nDownloading cosign for Linux")
        url = "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
        output_path = 'cosign'
        cosign_executable = "./cosign"
    try:
        # Send a GET request to the URL
        response = requests.get(url, allow_redirects=True)
        response.raise_for_status()  # Raise an error for bad responses

        with open(output_path, 'wb') as file:
            file.write(response.content)

        print(f'Successfully downloaded {output_path}')
    except requests.exceptions.RequestException as e:
        print(f'Error downloading file: {e}')
    try: 
        if os.name == 'posix': os.chmod(cosign_executable, 0o755)
        print("Cosign installed")
    except Exception as e:
        print(f'Error moving and changing file permissions: {e}')
    print()

def is_interactive():
    return sys.stdout.isatty() and sys.stdin.isatty()

def detect_ci_environment():
    print("Environment detected ", end="")
    if os.getenv('GITLAB_CI'):
        return "GitLab CI"
    elif os.getenv('GITHUB_ACTIONS'):
        return "GitHub Actions"
    else:
        return "Local or Unknown Environment"

def main():

    parser = argparse.ArgumentParser(description="Sign an artifact using STaaS (https://staas.excid.io)\nA path to an artifact is provided, and its digest is sent to STaaS. STaaS then returns the signature in a bundle.")
    subparsers = parser.add_subparsers(dest='command')

    sign_image_parser = subparsers.add_parser('sign-image', help='Sign a container image and attach it on the container image')
    sign_image_parser.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    sign_image_parser.add_argument('-c', '--comment', type=str, metavar='', required=False, default='Signed Image w/ STaaS CLI', help='A comment to accompany the signing (staas-specific info, not related to signature)')
    sign_image_parser.add_argument('-o', '--output', type=str, metavar='', required=False, default='output.bundle', help='Name of the bundle output file (default is output.bundle)')
    sign_image_parser.add_argument('--upload', default='True', metavar='', required=False, help='Attach the signature on the OCI registry (default is True)')
    sign_image_parser.add_argument('image', type=str, metavar='', help='Image to sign. Provide full URL to container registry e.g., registry.gitlab.com/some/repository')

    sign_blob_parser = subparsers.add_parser('sign-blob', help='Sign a blob (arbitrary artifact)')
    sign_blob_parser.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    sign_blob_parser.add_argument('-c', '--comment', type=str, metavar='', required=False, default='Signed Blob w/ STaaS CLI', help='A comment to accompany the signing (staas-specific info, not related to signature)')
    sign_blob_parser.add_argument('-o', '--output', type=str, metavar='', required=False, default='output.bundle', help='Name of the bundle output file (default is output.bundle)')
    sign_blob_parser.add_argument('artifact', type=str, metavar='', help='Path to the artifact to sign')

    attest_parser = subparsers.add_parser('attest-image', help='Create an attestation for a container image. Crafts in-toto statements, signs them, and creates a DSSE envelope which is attached to the image')
    attest_parser.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    attest_parser.add_argument('-p','--predicate', type=str, metavar='', required=True, help='Predicate of in-toto statement')
    attest_parser.add_argument('-y','--predicate-type', type=str, metavar='', dest='predicate_type', required=True, help='Predicate type of in-toto statement (provide URIs like https://cyclonedx.org/bom, https://slsa.dev/provenance/v1 etc)')
    attest_parser.add_argument('-c', '--comment', type=str, metavar='', required=False, default='Attested Image w/ STaaS CLI', help='A comment to accompany the signing (staas-specific info, not related to signature)')
    attest_parser.add_argument('-oa', '--output-attestation', type=str, metavar='', dest='output_attestation', required=False, default='dsse-output.att', help='Name of attestation output file (default is dsse-output.att)')
    attest_parser.add_argument('-ob', '--output-bundle', type=str, metavar='', dest='output_bundle', required=False, default='output.bundle', help='Name of the bundle output file (default is output.bundle)')
    attest_parser.add_argument('--upload', default='True', metavar='', required=False, help='Attach the signature on the OCI registry (default is True)')
    attest_parser.add_argument('image', type=str, metavar='', help='Image to attest. Provide full URL to container registry e.g., registry.gitlab.com/some/repository')

    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    if is_interactive():
        print("Interactive mode detected")
    else:
        print("Non-interactive mode detected")

    detect_ci_environment()
    
    global cosign_executable
    cosign_executable = "cosign"
    cosign_exists = os.system("cosign version > /dev/null 2>&1")  # check if cosign exists but hide the stdout
    if cosign_exists != 0:
        download_cosign()


    if args.command == 'sign-image':
        if args.upload in {'True', 'true', 'y', 'yes', 'Y'}:
            args.upload = True
        elif args.upload in {'False', 'false', 'n', 'no', 'N'}:
            args.upload = False
        else:
            print("Please provide \"true\" or \"false\" for upload option")
            os._exit(1)
        sign_image(args.image, args.token, args.comment, args.output, args.upload, args.verbose)
    elif args.command == 'sign-blob':
        sign_blob(args.artifact, args.token, args.comment, args.output, args.verbose)
    elif args.command == 'attest-image':
        if args.upload in {'True', 'true', 'y', 'yes', 'Y'}:
            args.upload = True
        elif args.upload in {'False', 'false', 'n', 'no', 'N'}:
            args.upload = False
        else:
            print("Please provide \"true\" or \"false\" for upload option")
        attest(args.image, args.predicate, args.predicate_type, args.token, args.comment, args.output_attestation, args.output_bundle, args.upload, args.verbose)
    else:
        parser.print_help()
        os._exit(0)

if __name__ == "__main__":
    main()