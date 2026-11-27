# A protocol simulator for the network survey test (test/netsurvey/run.sh).
FROM python:3.12-slim
RUN pip install --no-cache-dir "cpppo==5.2.5"
CMD ["python","-m","cpppo.server.enip","--address","0.0.0.0:44818","-v","Speed=INT[1]"]
