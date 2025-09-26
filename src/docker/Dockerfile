FROM python:3-slim
ENV PYTHONUNBUFFERED=1
LABEL authors=Harry_Pootha

ARG APP_USER=appuser
ARG UID=10001
ENV DATA_DIR=/openssl-certs
ENV SLEEP_DELAY=5
ENV MODE=poll
ENV PASSPHRASE=dummy
ENV GENERATE=false

WORKDIR /app

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    ${APP_USER}

RUN mkdir ${DATA_DIR}
RUN chown ${APP_USER}:${APP_USER} ${DATA_DIR}

# I HAVE to copy this comment from the docker guide I copied this from, because I think this is an ingenious way
# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /root/.cache/pip to speed up subsequent builds.
# Leverage a bind mount to requirements.txt to avoid having to copy them into
# into this layer.

# HELL, this makes sure you have all the requirements installed without having to copy the requirements
# It utilizes smart speed up and inflates nothing
# I like this so so much

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirements.txt,target=requirements.txt \
    python -m pip install -r requirements.txt

# Switch to the non-privileged user to run the application.
USER ${APP_USER}

# Copy the source code into the container.
COPY ./app/ .

ENTRYPOINT ["python", "main.py"]