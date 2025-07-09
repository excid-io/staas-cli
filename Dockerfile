FROM docker

RUN apk --no-cache add curl jq python3

RUN curl -O https://bootstrap.pypa.io/get-pip.py 

RUN python3 get-pip.py --break-system-packages

WORKDIR /staas

COPY staas-cli.py requirements.txt /staas/

RUN pip install -r requirements.txt

CMD [ "python3", "/staas/staas-cli.py" ]
