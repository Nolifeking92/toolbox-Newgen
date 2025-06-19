FROM debian:stable-slim
RUN apt-get update && apt-get install -y fping && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["fping"] 