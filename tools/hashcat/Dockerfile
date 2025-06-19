FROM debian:stable-slim
RUN apt-get update && apt-get install -y hashcat && rm -rf /var/lib/apt/lists/*
CMD ["hashcat", "--help"]
ENTRYPOINT ["hashcat"] 