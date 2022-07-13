FROM ubuntu:20.04 AS builder

RUN apt-get update && apt install -y python3-dev python3-pip
RUN pip3 install pipenv
COPY Pipfile Pipfile.lock /app/

WORKDIR /app
ENV PIPENV_VENV_IN_PROJECT=1
RUN pipenv install

#####################################
FROM ubuntu:20.04

RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt install -y \
        python3 \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY . /app/

ENV PATH="$PATH:/app/.venv/bin"
ENV VIRTUAL_ENV=/app/.venv

EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "main:app"]
