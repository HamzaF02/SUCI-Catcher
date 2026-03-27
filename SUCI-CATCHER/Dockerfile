FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libsctp-dev \
    lksctp-tools \
    iproute2 \
    && pip install pysctp pycrate

WORKDIR /app
COPY suci-probe.py .

CMD ["python", "-u", "suci-probe.py"]