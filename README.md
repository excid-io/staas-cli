# STaaS CLI

A command-line tool for signing artifacts using STaaS (Signing as a Service). This tool currently supports two commands: signing container images and signing arbitrary blobs.

Prerequisites: 
1. `docker` exists in your system
2. `cosign` exists in your system (staas-cli downloads it for you if it does not exist)  

```text
$ python3 staas-cli.py -h

usage: staas-cli.py [-h] [-v] {sign-image,sign-blob} ...

Sign an artifact using STaaS (https://staas.excid.io) A path to an artifact is provided, and its
digest is sent to STaaS. STaaS then returns the signature in a bundle.

positional arguments:
  {sign-image,sign-blob}
    sign-image          Sign a container image
    sign-blob           Sign a blob (arbitrary artifact)

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output
```

## Use

The commands available right now are:
- sign-image
- sign-blob

### Signing container images

Command:

```sh
python3 staas-cli.py sign-image -t STAAS_API_TOKEN -c COMMENT -o BUNDLE_OUTPUT_FILE IMAGE
```
This command signs a container image and uploads the signature on the OCI registry.

### Signing blobs (arbitrary artifacts)

Command:

```sh
python3 staas-cli.py sign-blob -t STAAS_API_TOKEN -c COMMENT -o BUNDLE_OUTPUT_FILE PATH_TO_ARTIFACT
```
This command signs an artifact provided and stores the bundle (that contains the signature) locally.

## Installation

To use the signing tool, clone the repository and install the required dependencies:

```bash
git clone https://github.com/yourusername/signing-tool.git
cd signing-tool
pip install -r requirements.txt
