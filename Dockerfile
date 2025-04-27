FROM python:3.9-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8000
# Provide a default secret key for build-time. This is only used during the image build.
ARG BUILD_SECRET_KEY="temporary_secret_key_change_me"
ENV SECRET_KEY=$BUILD_SECRET_KEY

# install system dependencies
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    gcc \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt /app/
RUN pip install -r requirements.txt

# Create necessary directories
RUN mkdir -p staticfiles
RUN mkdir -p static


COPY . /app

EXPOSE 8000
# Create static directory and collect static files
RUN python manage.py collectstatic --noinput --clear


ENTRYPOINT [ "gunicorn", "core.wsgi:application", "-b", "0.0.0.0:8000"]