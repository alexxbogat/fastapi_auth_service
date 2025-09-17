FROM python:3.13-slim

RUN apt-get update && apt-get install -y build-essential libpq-dev

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . /app

CMD ["python", "main.py"]