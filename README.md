# STaaS CLI

A command-line tool for signing artifacts using STaaS (Signing as a Service). This tool currently supports two commands: signing container images and signing arbitrary blobs.

Prerequisites: 
1. `docker` exists in your system
2. `cosign` exists in your system (staas-cli downloads it for you if it does not exist)  

```text
$ python3 staas-cli.py -h

usage: staas-cli.py [-h] [-v] {sign-image,sign-blob,attest-image,issue-certificate} ...

Sign container images and artifacts using STaaS (https://staas.excid.io). A container image
URL or a path to an artifact is provided, and its digest is sent to STaaS. STaaS then
returns the signature in a bundle. For container images, signatures and attestations can be
attached to the image on the OCI registry.

positional arguments:
  {sign-image,sign-blob,attest-image,issue-certificate}
    sign-image          Sign a container image and attach it on the container image
    sign-blob           Sign a blob (arbitrary artifact)
    attest-image        Create an attestation for a container image. Crafts in-toto
                        statements, signs them, and creates a DSSE envelope which is
                        attached to the image
    issue-certificate   Generate a key-pair and ask STaaS CA to issue a public key
                        certificate

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output
```

## Usage

The commands available right now are:
- sign-image
- sign-blob
- attest-image
- issue-certificate

### Signing container images

```sh
python3 staas-cli.py sign-image $IMAGE:$TAG --token $STAAS_API_TOKEN --comment $COMMENT --output $BUNDLE_OUTPUT_FILE 
```
This command signs a container image and uploads the signature on the OCI registry. Verify with:

```sh
cosign verify $IMAGE:$TAG --certificate-identity $STAAS_EMAIL --certificate-oidc-issuer "https://staas.excid.io" --certificate-chain staas-ca.pem --insecure-ignore-sct
```

### Signing blobs (arbitrary artifacts)

```sh
python3 staas-cli.py sign-blob $PATH_TO_ARTIFACT --token $STAAS_API_TOKEN --comment $COMMENT --output $BUNDLE_OUTPUT_FILE 
```
This command signs an artifact provided and stores the bundle (that contains the signature) locally. This command signs a container image and uploads the signature on the OCI registry. Verify with:

```sh
cosign verify-blob $YOUR_FILE --certificate-identity $STAAS_EMAIL --certificate-oidc-issuer "https://staas.excid.io" --certificate-chain staas-ca.pem --bundle $BUNDLE_OUTPUT_FILE --insecure-ignore-sct 
```

### Attest container images

```sh
python3 staas-cli.py attest-image $IMAGE:$TAG --token $STAAS_API_KEY --predicate-type $PREDICATE_TYPE --predicate $PATH_TO_PREDICATE_FILE --root-ca-file $PATH_TO_CA_FILE --subject $STAAS_EMAIL
```
This command creates in-toto based attestations using STaaS. It accepts a file containing a predicate, and the predicate type for the in-toto statement. It generates a key pair locally, issues a public-key certificate with STaaS, attests and uploads the attestation on the OCI registry. The reason why a subject (the email associated with the STaaS token) is needed is because the short-lived certificate needs a subject field (CN/Common Name). If you are using staas-cli container image, the path to root CA file is `/staas/staas-ca.pem`. Verify with:

```sh
cosign verify-attestation $IMAGE:$TAG --type $PREDICATE_TYPE --certificate-identity $STAAS_EMAIL --certificate-oidc-issuer "https://staas.excid.io" --certificate-chain staas-ca.pem --certificate $CERT_FILE --insecure-ignore-sct
```

### Issue short-lived certificate

In case you want to use `cosign` with your own keys you can have STaaS generate the short-lived public key certificate for you.
```sh
python3 staas-cli.py issue-certificate --token $STAAS_TOKEN --subject $STAAS_EMAIL --output $CRT_OUTPUT_FILE
```
This will generate a key-pair locally and a CSR which is sent to STaaS. STaaS then returns the certificate which is stored locally. Consequently, you can use cosign for signing events.

```sh
cosign import-key-pair --key private.key
cosign sign --key import-cosign.key --certificate $CRT_OUTPUT_FILE $IMAGE:$TAG
```

## Installation

#### From releases

You can download the binaries from the repo's releases. Windows and Linux versions are supported.

```sh
# if on linux
wget https://github.com/excid-io/staas-cli/releases/download/main/staas-cli
chmod +x staas-cli
./staas-cli -h
# if on windows
Invoke-WebRequest -Uri "https://github.com/excid-io/staas-cli/releases/download/main/staas-cli.exe" -OutFile "staas-cli.exe"
.\staas-cli.exe -h
```

#### Container image
You can run the container image uploaded on the repo's packages. It has pre-installed all the runtime dependencies. Useful for automation (CI/CD) scenarios like GitLab CI.

```sh
docker pull ghcr.io/excid-io/staas-cli:latest
docker run -it ghcr.io/excid-io/staas-cli:latest /bin/sh
python3 /staas/staas-cli.py -h
```

#### Set up from scratch
To use the signing tool, clone the repository and install the required dependencies:

```bash
git clone https://github.com/excid-io/staas-cli.git
cd signing-tool
pip install -r requirements.txt
```

## STaaS CA

In some signing scenarios and in all verifications, you need to provide the STaaS CA pem file to cosign. You can get this file by running:
```sh
wget http://staas.excid.io/Sign/Certificate -O staas-ca.pem
```
