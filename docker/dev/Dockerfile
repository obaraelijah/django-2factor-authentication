# Pull official base image 
FROM python:3.10-slim

# Set working dir
WORKDIR /app

# Set env vars
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update \
    && apt-get install -y gcc python3-dev musl-dev libmagic1 libffi-dev netcat-traditional \
    && pip install Pillow

COPY ./app/requirements ./requirements

# Install dependencies
COPY ./app/requirements ./requirements
RUN pip install --upgrade pip
RUN pip install -r ./requirements/dev.txt

# Copy entrypoint
COPY ./docker/dev/entrypoint /entrypoint

RUN chmod +x /entrypoint

COPY ./app /app

ENTRYPOINT [ "/entrypoint" ]