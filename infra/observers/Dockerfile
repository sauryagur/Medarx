# The byte-recording observer (component I, first observer).
#
# A stand-in provider, not a model. It answers the OpenAI chat-completions shape
# so the gateway can send to it unchanged, and it writes every request body it
# receives to disk before it replies. Nothing in this image contacts a model,
# and there is no model client in it to contact one with.
FROM python:3.13-slim-bookworm

# No root: this container receives synthetic radiology text and writes it to a
# bind-mounted volume, and neither needs privilege. The record directory is the
# one place the process writes, so it is created and given to the unprivileged
# user the server drops to.
RUN useradd --create-home --uid 10001 observer

WORKDIR /srv
COPY observer.py /srv/observer.py
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir --requirement /srv/requirements.txt \
 && mkdir -p /records \
 && chown -R observer:observer /records /srv

USER observer

ENV OBSERVER_RECORD_DIR=/records \
    OBSERVER_HOST=0.0.0.0 \
    OBSERVER_PORT=8080 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# The record directory is a volume, not the container's writable layer: the
# evidence has to outlive the observer, and a container that is removed with its
# evidence is an observer that proves nothing.
VOLUME ["/records"]

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=5 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

ENTRYPOINT ["python", "/srv/observer.py"]
