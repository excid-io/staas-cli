FROM docker

RUN apk --no-cache add curl jq python3 py3-pip cosign

WORKDIR /staas

COPY staas-cli.py requirements.txt oras /staas/

RUN pip3 install -r requirements.txt --break-system-packages

RUN chmod +x /staas/staas-cli.py

ENV PATH="/staas:${PATH}"

RUN mv /staas/oras /usr/bin/oras

CMD [ "python3", "/staas/staas-cli.py" ]