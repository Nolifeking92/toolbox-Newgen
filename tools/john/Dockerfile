FROM debian:stable-slim
RUN apt-get update && apt-get install -y john && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["john"] 