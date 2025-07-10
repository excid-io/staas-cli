FROM docker

RUN apk --no-cache add curl jq python3 py3-pip cosign

WORKDIR /staas

COPY staas-cli.py requirements.txt /staas/

RUN pip3 install -r requirements.txt --break-system-packages

CMD [ "python3", "/staas/staas-cli.py" ]