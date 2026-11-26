# A protocol simulator for the network survey test (test/netsurvey/run.sh).
FROM alpine:3.20
RUN apk add --no-cache net-snmp
COPY snmpd.conf /etc/snmp/snmpd.conf
CMD ["snmpd","-f","-Lo","-C","-c","/etc/snmp/snmpd.conf"]
