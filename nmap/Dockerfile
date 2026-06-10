FROM python:3.11-slim

# Enable non-free repo (needed for nikto), install apt tools
RUN echo "deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    apt-get update && apt-get install -y \
    nmap nikto whatweb sslscan gobuster ffuf curl git \
    && rm -rf /var/lib/apt/lists/*

# Go runtime for ProjectDiscovery tools
RUN apt-get update && apt-get install -y golang-go && rm -rf /var/lib/apt/lists/*

ENV PATH="$PATH:/root/go/bin"

# Go-based tools
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest

# wafw00f via pip (no apt package on trixie)
RUN pip install --no-cache-dir wafw00f

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
