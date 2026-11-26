# A protocol simulator for the network survey test (test/netsurvey/run.sh).
FROM python:3.12-alpine
RUN pip install --no-cache-dir "bacpypes3==0.0.102"
COPY device.py /device.py
CMD ["python","/device.py"]
