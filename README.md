# STaaS CLI

A command-line tool for signing artifacts using STaaS (Signing as a Service). This tool currently supports two commands: signing container images and signing arbitrary blobs.

Prerequisites: 
1. `docker` exists in your system
2. `cosign` exists in your system (staas-cli downloads it for you if it does not exist)  
3. `oras` exists in your system (used for uploading attestations)

```text
$ python3 staas-cli.py -h

usage: staas-cli.py [-h] [-v] {sign-image,sign-blob,attest-image} ...

Sign an artifact using STaaS (https://staas.excid.io) A path to an artifact is
provided, and its digest is sent to STaaS. STaaS then returns the signature in
a bundle.

positional arguments:
  {sign-image,sign-blob,attest-image}
    sign-image          Sign a container image and attach it on the container
                        image
    sign-blob           Sign a blob (arbitrary artifact)
    attest-image        Create an attestation for a container image. Crafts
                        in-toto statements, signs them, and creates a DSSE
                        envelope which is attached to the image

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output
```

## Usage

The commands available right now are:
- sign-image
- sign-blob
- attest-image

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
python3 staas-cli.py attest-image $IMAGE:$TAG --token $STAAS_API_TOKEN --comment $COMMENT --output-bundle $BUNDLE_OUTPUT_FILE --output-attestation $ATTESTATION_OUTPUT_FILE
```
This command creates in-toto based attestations using STaaS. It accepts a file containing a predicate, and a predicate type for a specific image. It crafts the in-toto statement as a json, then signs it with STaaS, and finally creates the DSSE envelope which is attached to the image repository. Verify with:

```sh
cosign verify-attestation $IMAGE:$TAG --type $PREDICATE_TYPE --certificate-identity $STAAS_EMAIL --certificate-oidc-issuer "https://staas.excid.io" --certificate-chain staas-ca.pem --certificate $CERT_FILE --insecure-ignore-sct
```


## Installation

#### From releases

You can download the binaries from the repo's releases. Windows and Linux versions are supported.

```sh
# if on linux
chmod +x staas-cli
./staas-cli
# if on windows
.\staas-cli.exe
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

In order to run verifications, you need to provide the STaaS CA pem file to cosign. You can get this file by running:
```sh
wget http://staas.excid.io/Sign/Certificate -O staas-ca.pem
```
