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

def sign_image(image, token, comment, bundle_output_file, upload):
    # 1. Generate payload with cosign
    try:
        result = subprocess.run(f'{cosign_executable} generate {image} > payload.json', shell=True, check=True, text=True, capture_output=True)
        if result.stdout != "": print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"{error_str}{e.stderr}")
        os._exit(1)
    
    print("Generated image payload json ")
    payload_file = 'payload.json'
    # 2. Sign image with STaaS
    sign_blob(payload_file, token, comment, bundle_output_file)

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
        command = [
            cosign_executable, 
            'attach', 
            'signature', 
            image,
            '--signature', sig_file,
            '--payload', payload_file,
            '--certificate-chain', ca_file,
            '--certificate', cert_file,
            '--rekor-response', rekor_file
        ]
        try:
            result = subprocess.run(command, check=True, text=True, capture_output=True)
            if result.stdout != "": print(result.stdout)
            print("Attached signature to image " + image)
        except subprocess.CalledProcessError as e:
            print(f"{error_str}{e.stderr}")
            print("Could not attach signature, exiting")
            os._exit(2)
    else: 
        print(f"{warning_str}Upload option set to \"False\", skipping uploading")

    os.remove(payload_file)
    os.remove(sig_file)
    os.remove(cert_file)
    os.remove(rekor_file)
    os.remove(ca_file)

def sign_blob(artifact, token, comment, output):
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

    response = requests.request("POST", url + "Api/Sign", headers=headers, data=payload)

    print("Signed artifact " + artifact)
    with open(output, "w") as text_file:
        text_file.write(response.text)
    print("Wrote bundle to " + output)

def attest(image, predicate, predicate_type, token, subject, root_ca_file):
    # safety check: remove old keys and certificates (leftovers)
    files_to_delete = [
        "private.key",
        "public.key",
        "staas.csr",
        "staas.crt",
        "import-cosign.key",
        "import-cosign.pub"
    ]
    for file in files_to_delete:
        try:
            os.remove(file)
        except:
            pass
    # 1. run `staas-cli issue-certificate`, 2. run `cosign import-key-pair`, 3. run `cosign attest`
    # 1. generate key pair and certificate 
    issue(token, subject, "staas.crt")  # this stores private.key, public.key, staas.csr and staas.crt in the same directory
    
    # 2. import key pair in cosign
    try:
        if os.name == 'nt':
            result = subprocess.run(f"$env:COSIGN_PASSWORD = Get-Random", shell=True, text=True, check=True, capture_output=True)
        elif os.name == 'posix':
            result = subprocess.run(f"COSIGN_PASSWORD=$RANDOM", shell=True, text=True, check=True, capture_output=True)
        if result.stdout != "": print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"{error_str}{e.stderr}")
        os._exit(1) 
    try:
        if os.name == 'nt':
            result = subprocess.run(f"echo $env:COSIGN_PASSWORD | {cosign_executable} import-key-pair --key private.key", shell=True, text=True, check=True, capture_output=True)
        elif os.name == 'posix':
            result = subprocess.run(f"echo $COSIGN_PASSWORD | {cosign_executable} import-key-pair --key private.key", shell=True, text=True, check=True, capture_output=True)
        if result.stdout != "": print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"{error_str}{e.stderr}")
        os._exit(2) 

    # 3. attest
    try:
        if os.name == 'nt':
            result = subprocess.run(f"echo $env:COSIGN_PASSWORD | {cosign_executable} attest {image} --key import-cosign.key --type {predicate_type} --predicate {predicate} --certificate staas.crt --certificate-chain {root_ca_file} -y", shell=True, text=True, check=True, capture_output=True)
        elif os.name == 'posix':
            result = subprocess.run(f"echo $COSIGN_PASSWORD | {cosign_executable} attest {image} --key import-cosign.key --type {predicate_type} --predicate {predicate} --certificate staas.crt --certificate-chain {root_ca_file} -y", shell=True, text=True, check=True, capture_output=True)
        if result.stdout != "": print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"{error_str}{e.stderr}")
        os._exit(3) 

    print("Uploaded attestation for image " + image)

    subprocess.run("unset COSIGN_PASSWORD", shell=True)    
    command = [
        "shred", "-u", 
        "private.key", 
        "public.pub", 
        "staas.csr", 
        "staas.crt", 
        "import-cosign.key", 
        "import-cosign.pub"
    ]
    subprocess.run(command, check=True)

def issue(token, subject, cert_output_file):
    # 1. Generate key-pair and CSR
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import Name, NameAttribute, CertificateSigningRequestBuilder
    import cryptography.x509 as x509

    # Generate an EC private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Save the private key to a file (unencrypted)
    with open("private.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # No encryption
        ))
    print("Generated private key")

    # Generate the public key
    public_key = private_key.public_key()

    # Save the public key to a file
    with open("public.pub", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Generated public key")

    # Create a CSR
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)])
    csr = CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256(), default_backend())

    # Save the CSR to a file
    with open("staas.csr", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("Generated CSR")

    # Generate short-lived certificate with STaaS
    url="https://staas.excid.io/"
    headers = {
        'Content-Type': 'text/plain',
        'Authorization': 'Basic ' + token
    }

    with open("staas.csr", "rb") as file:
        data = file.read()

    response = requests.request("POST", url + "Api/Issue", headers=headers, data=data)
    
    print("Issued short-lived certificate")
    with open(cert_output_file, "w") as crt_file:
        crt_file.write(response.text)
    print("Stored certificate in file " + cert_output_file)

def download_ca_pem(output_file):
    from tqdm import tqdm
    
    url = "http://staas.excid.io/Sign/Certificate"
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))

        with open(output_file, 'wb') as file:
            # Create a progress bar
            with tqdm(total=total_size, unit='B', unit_scale=True, desc=output_file) as bar:
                for data in response.iter_content(chunk_size=1024):
                    file.write(data)
                    bar.update(len(data))  # Update the progress bar

        print(f'Successfully downloaded {output_file}')    
    except requests.exceptions.RequestException as e:
        print(f'{error_str}Error downloading file: {e}')

def download_cosign():
    from tqdm import tqdm

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
        response = requests.get(url, stream=True, allow_redirects=True)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))

        with open(output_path, 'wb') as file:
            # Create a progress bar
            with tqdm(total=total_size, unit='B', unit_scale=True, desc=output_path) as bar:
                for data in response.iter_content(chunk_size=1024):
                    file.write(data)
                    bar.update(len(data))  # Update the progress bar

        print(f'Successfully downloaded {output_path}')
    except requests.exceptions.RequestException as e:
        print(f'{error_str}Error downloading file: {e}')
    try: 
        if os.name == 'posix': os.chmod(cosign_executable, 0o755)
        print("Cosign installed")
    except Exception as e:
        print(f'Error moving and changing file permissions: {e}')

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
    sign_image_parser.add_argument('-c', '--comment', type=str, metavar='', required=False, default='Signed Image w/ STaaS CLI', help='A comment to accompany the signing (STaaS-specific info, not related to signature)')
    sign_image_parser.add_argument('-o', '--output', type=str, metavar='', required=False, default='output.bundle', help='Name of the bundle output file (default is output.bundle)')
    sign_image_parser.add_argument('--upload', default='True', metavar='', required=False, help='Attach the signature on the OCI registry (default is True)')
    sign_image_parser.add_argument('image', type=str, metavar='', help='Image to sign. Provide full URL to container registry e.g., registry.gitlab.com/some/repository')

    sign_blob_parser = subparsers.add_parser('sign-blob', help='Sign a blob (arbitrary artifact)')
    sign_blob_parser.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    sign_blob_parser.add_argument('-c', '--comment', type=str, metavar='', required=False, default='Signed Blob w/ STaaS CLI', help='A comment to accompany the signing (STaaS-specific info, not related to signature)')
    sign_blob_parser.add_argument('-o', '--output', type=str, metavar='', required=False, default='output.bundle', help='Name of the bundle output file (default is output.bundle)')
    sign_blob_parser.add_argument('artifact', type=str, metavar='', help='Path to the artifact to sign')

    attest_parser = subparsers.add_parser('attest-image', help='Create an attestation for a container image. Crafts in-toto statements, signs them, and creates a DSSE envelope which is attached to the image')
    attest_parser.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    attest_parser.add_argument('-s','--subject', type=str, metavar='', required=True, help='Subject that attests the image (used to issue short-lived certificate by STaaS)')
    attest_parser.add_argument('-p','--predicate', type=str, metavar='', required=True, help='Path to predicate file')
    attest_parser.add_argument('-y','--predicate-type', type=str, metavar='', dest='predicate_type', required=True, help='Predicate type of in-toto statement (provide full URIs such as https://cyclonedx.org/bom, https://slsa.dev/provenance/v1 etc)')
    attest_parser.add_argument('-r','--root-ca-file', type=str, metavar='', dest='root_ca_file', required=True, help='Path to STaaS CA file (used to attach it on attestation metadata for verification purposes)')
    attest_parser.add_argument('image', type=str, metavar='', help='Image to attest. Provide full URL to container registry e.g., registry.gitlab.com/some/repository')

    issue_cert_parser = subparsers.add_parser('issue-certificate', help='Generate a key-pair and ask STaaS CA to issue a public key certificate')
    issue_cert_parser.add_argument('-t','--token', type=str, metavar='', required=True, help='Authorization token to access STaaS API')
    issue_cert_parser.add_argument('-s', '--subject', type=str, metavar='', required=True, help='Subject requesting the certificate (set it to STAAS_EMAIL owning the token)')
    issue_cert_parser.add_argument('-o', '--output', type=str, metavar='', required=False, default='staas.crt', help='Name of the .crt output file (default is staas.crt)')

    args = parser.parse_args()

    # ======== SEARCH FOR COSIGN IN SYSTEM ========
    global cosign_executable
    cosign_executable = "cosign"
    cosign_exists = os.system(f"{cosign_executable} version > /dev/null 2>&1")  # check if cosign exists in PATH but hide the stdout
    # if cosign not in PATH, search for it in the current directory
    if cosign_exists != 0:
        if os.name == 'nt':
            cosign_executable = ".\\cosign.exe"
        elif os.name == 'posix':
            cosign_executable = "./cosign"
        if os.path.exists(cosign_executable):
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
        sign_image(args.image, args.token, args.comment, args.output, args.upload)
    elif args.command == 'sign-blob':
        sign_blob(args.artifact, args.token, args.comment, args.output)
    elif args.command == 'attest-image':
        attest(args.image, args.predicate, args.predicate_type, args.token, args.subject, args.root_ca_file)
    elif args.command == 'issue-certificate':
        issue(args.token, args.subject, args.output)
    else:
        parser.print_help()
        os._exit(0)

if __name__ == "__main__":
    main()