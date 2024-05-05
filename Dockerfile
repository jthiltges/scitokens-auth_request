FROM python:3-alpine

WORKDIR /app
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

COPY authorizer.py /app

#CMD fastapi dev authorizer.py --host 0.0.0.0
CMD fastapi run authorizer.py --host 0.0.0.0
EXPOSE 8000
