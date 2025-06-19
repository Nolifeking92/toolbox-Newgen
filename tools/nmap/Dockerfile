FROM debian:stable-slim
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["nmap"] 