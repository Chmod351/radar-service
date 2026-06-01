FROM kalilinux/kali-last-release

ENV DEBIAN_FRONTEND=noninteractive
RUN echo "deb http://archive.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
# Repositorios y actualizaciones
RUN apt-get update && apt-get upgrade -y && apt-get install -y --fix-missing \
    bash \
    curl \
    jq \
    dnsutils \
    nmap \
    whatweb \
    exploitdb \
    whois\
    ruby-full \
    build-essential \
    subfinder \
    httpx-toolkit \
    dnsx \
    assetfinder \
    && rm -rf /var/lib/apt/lists/*

# --- INSTALACIÓN DE BUN ---
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.bun/bin:/root/go/bin"

WORKDIR /app

COPY package.json bun.lockb* ./
RUN bun install

COPY . .

RUN chmod -R 755 /app

ENTRYPOINT ["bun"]
CMD ["run","/app/src/core/orchestrator.ts"]
