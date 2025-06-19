FROM python:3.10-slim
RUN apt-get update && apt-get install -y gcc python3-dev curl libcurl4-openssl-dev libssl-dev && pip install setuptools "pip<24.1" wfuzz
ENTRYPOINT ["wfuzz"] 