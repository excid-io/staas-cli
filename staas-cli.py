#!/usr/bin/python3
import hashlib
import base64
import os
import json
import sys
import subprocess
import argparse
import requests

# global vars
ca_file = 'staas-ca.pem'
cosign_executable = ""
error_str = "[!] -- Error\n\t"
warning_str = "[!] -- Warning\n\t"
info_str = "[!] -- Info\n\t"

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
            print(f"{error_str}Could not attach signature")
    else: 
        print(f"{warning_str}Upload option set to \"False\", skipping uploading")

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
    # 1.a Get digest of provided image
    digest = get_image_digest(image)
    if digest:
        print(f"The digest of the image is: {digest}")
    else:
        print(f"{error_str}Failed to obtain the digest.")
        return

    # 1.b Predicate is stored in a file, so we need to read it an store it inside the json field.
    image_ref = image.split(':')[0]  # remove the ":TAG" from the image string
    intoto_statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": predicate_type,
        "subject": [{
            "name": image_ref,
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
        print(f"{warning_str}Upload option set to \"False\", skipping uploading")
        return

    annotations = {
        att_output_file : {
            "dev.cosignproject.cosign/signature": "",
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
    annotations["dev.cosignproject.cosign/signature"] = signature

    annotations_file = 'annotations.json'
    with open(annotations_file, 'w') as ann_file:
        json.dump(annotations, ann_file, indent=4)
    print("Created annotations", flush=True)

    # 6. Attach
    registry = image.split('/')[0]
    # subprocess.run(f"oras tag {image} {image_ref}:sha256-{digest}.att", shell=True)
    subprocess.run(f"oras push {image_ref}:sha256-{digest}.att --artifact-type application/vnd.dsse.envelope.v1+json {att_output_file}:application/vnd.dsse.envelope.v1+json --annotation predicateType={intoto_statement['predicateType']} --annotation dev.sigstore.cosign/bundle={json.dumps(bundle_data['rekorBundle'])} --annotation dev.sigstore.cosign/certificate={cert} --annotation dev.sigstore.cosign/chain={ca_data} --annotation dev.cosignproject.cosign/signature={signature}", shell=True)
    print("Uploaded attestation", flush=True)

    os.remove(ca_file)

def issue(token, subject, cert_output_file, verbose):
    subprocess.run(f"openssl ecparam -name prime256v1 -genkey -noout -out private.key", shell=True)
    subprocess.run(f"openssl ec -in private.key -pubout -out public.pub", shell=True)
    print("Generated key pair")
    subprocess.run(f"openssl req -new -key private.key -subj \"/CN={subject}\" -out staas.csr", shell=True)
    print("Generated csr")
    
    url="https://staas.excid.io/"
    headers = {
    'Content-Type': 'text/plain',
    'Authorization': 'Basic ' + token
    }

    with open("staas.csr", "rb") as file:
        data = file.read()

    response = requests.request("POST", url + "Api/Issue", headers=headers, data=data)
    if verbose:
        print(response.text)
        print("Response code: " + str(response.status_code))
    
    print("Issued certificate")
    with open(cert_output_file, "w") as crt_file:
        crt_file.write(response.text)

    print("Wrote certificate in file " + cert_output_file)


def download_ca_pem(output_file):
    url = "http://staas.excid.io/Sign/Certificate"
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(output_file, 'wb') as file:
            file.write(response.content)
        print(f'Successfully downloaded {output_file}')
    except requests.exceptions.RequestException as e:
        print(f'{error_str}Error downloading file: {e}')

def download_cosign():
    global cosign_executable
    print(f"{info_str}Cosign not found in PATH, proceeding to download it")
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
        print(f'{error_str}Error downloading file: {e}')
    try: 
        if os.name == 'posix': os.chmod(cosign_executable, 0o755)
        print("Cosign installed")
    except Exception as e:
        print(f'Error moving and changing file permissions: {e}')
    print()

def is_interactive():
    return sys.stdout.isatty() and sys.stdin.isatty()

def detect_ci_environment():
    print("Environment detected: ", end="")
    if os.getenv('GITLAB_CI'):
        print("GitLab CI")
    elif os.getenv('GITHUB_ACTIONS'):
        print("GitHub Actions")
    else:
        print("local or unknown environment")
    
def get_image_digest(image):
    command = "docker buildx imagetools inspect " + image + " | awk '/Digest:/{split($2,a,\":\"); print a[2]}'"
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
                print(f"{error_str}Command executed successfully but returned no digest.")
                digest = None
    except Exception as e:
        print(f"{error_str}An error occurred while running the command, and could not fetch the digest: {e}")
        digest = None
    return digest    


def main():
    # ======== PARSER ARGUMENTS ========
    parser = argparse.ArgumentParser(description="Sign container images and artifacts using STaaS (https://staas.excid.io). A container image URL or a path to an artifact is provided, and its digest is sent to STaaS. STaaS then returns the signature in a bundle. For container images, signatures and attestations can be attached to the image on the OCI registry.")
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

    issue_cert = subparsers.add_parser('issue-certificate', help='Generate a key-pair and ask STaaS CA to issue a public key certificate')
    issue_cert.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    issue_cert.add_argument('-s', '--subject', type=str, metavar='', required=False, help='Subject requesting the certificate (set it to STAAS_EMAIL owning the token)')
    issue_cert.add_argument('-o', '--output', type=str, metavar='', required=False, default='staas.crt', help='Name of the .crt output file (default is staas.crt)')

    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    # if is_interactive():
    #     print("Interactive mode detected")
    # else:
    #     print("Non-interactive mode detected")
    # detect_ci_environment()

    # ======== SEARCH FOR COSIGN IN SYSTEM ========
    global cosign_executable
    if os.name == 'nt':
        cosign_executable = ".\\cosign.exe"
    elif os.name == 'posix':
        cosign_executable = "./cosign"
    cosign_exists = os.system("cosign version > /dev/null 2>&1")  # check if cosign exists in PATH but hide the stdout
    # if cosign not in PATH, search for it in the current directory
    if cosign_exists != 0:
        if args.verbose: print("Cosign not in PATH")
        if os.path.exists(cosign_executable) and args.verbose:
            print("Cosign found in current directory")
        else:
            download_cosign()
        
    # ======== MAIN LOGIC START ========
    if args.command == 'sign-image':
        if args.upload in {'True', 'true', 'y', 'yes', 'Y'}:
            args.upload = True
        elif args.upload in {'False', 'false', 'n', 'no', 'N'}:
            args.upload = False
        else:
            print(f"{error_str}Please provide \"true\" or \"false\" for upload option")
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
            print(f"{error_str}Please provide \"true\" or \"false\" for upload option")
            os._exit(1)
        attest(args.image, args.predicate, args.predicate_type, args.token, args.comment, args.output_attestation, args.output_bundle, args.upload, args.verbose)
    elif args.command == 'issue-certificate':
        issue(args.token, args.subject, args.output, args.verbose)
    else:
        parser.print_help()
        os._exit(0)

if __name__ == "__main__":
    main()