# A protocol simulator for the network survey test (test/netsurvey/run.sh):
# an IPP Everywhere printer (CUPS ippeveprinter) with two toner levels.
# avahi runs only because ippeveprinter will not start without DNS-SD.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends cups-ipp-utils avahi-daemon dbus && rm -rf /var/lib/apt/lists/*
COPY printer.conf /printer.conf
RUN printf '#!/bin/sh\nmkdir -p /run/dbus\ndbus-daemon --system\navahi-daemon -D --no-drop-root --no-rlimits\nsleep 1\nexec ippeveprinter -a /printer.conf -p 631 "Lab Printer"\n' > /start.sh && chmod +x /start.sh
CMD ["/start.sh"]
