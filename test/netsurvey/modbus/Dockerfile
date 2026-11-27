# A protocol simulator for the network survey test (test/netsurvey/run.sh).
FROM python:3.12-alpine
RUN pip install --no-cache-dir "pymodbus==3.8.6"
COPY server.py /server.py
CMD ["python","/server.py"]
