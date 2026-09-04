FROM python:3.11-slim

WORKDIR /agent

COPY sdk/python /agent/sdk/python
COPY demo-agent/agent.py /agent/agent.py
COPY infra/agent/probe.py /agent/probe.py

RUN pip install --no-cache-dir --break-system-packages httpx \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin aegis \
    && chown -R aegis:aegis /agent

USER 10001
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/agent/sdk/python

CMD ["python", "probe.py", "--wait"]
