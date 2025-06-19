FROM debian:stable-slim
RUN apt-get update && apt-get install -y aircrack-ng && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["aircrack-ng"] 