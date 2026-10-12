FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir dpkt
ENTRYPOINT ["python", "-m", "pcaphunter.cli"]
# docker run --rm -v $PWD/samples:/pcaps pcap-hunter /pcaps/synscan.pcapng -o /pcaps/out
