#!/usr/bin/env bash
# Runs a real network survey against protocol simulators on an isolated
# Docker network: net-snmp (v2c and v3, with Printer-MIB supplies), a
# pymodbus server with device identification, a bacpypes3 BACnet device,
# cpppo's EtherNet/IP simulator and CUPS's ippeveprinter. The survey runs
# from a container on the same --internal network, so no probe can reach
# anything else. Profinet has no simulator and is not exercised here.
#
#   test/netsurvey/run.sh                  # subnet 10.231.77.0/24
#   NETSURVEY_SUBNET=10.99.0 test/netsurvey/run.sh
#   NETSURVEY_CAPTURE=1 test/netsurvey/run.sh   # also refresh the fixtures
#
# Everything it creates is removed on exit.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
net="${NETSURVEY_SUBNET:-10.231.77}"
tag="nsv-$$"
work="$(mktemp -d)"
cleanup() {
  docker rm -f "$tag-tester" "$tag-snmp" "$tag-modbus" "$tag-bacnet" "$tag-enip" "$tag-ipp" >/dev/null 2>&1 || true
  docker network rm "$tag" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

for sim in snmpd modbus bacnet enip ipp; do
  docker build -q -t "mustra-netsurvey-$sim" "$here/$sim" >/dev/null
done
docker network create --internal --subnet "$net.0/24" "$tag" >/dev/null
docker run -d --name "$tag-snmp" --network "$tag" --ip "$net.11" mustra-netsurvey-snmpd >/dev/null
docker run -d --name "$tag-modbus" --network "$tag" --ip "$net.12" mustra-netsurvey-modbus >/dev/null
docker run -d --name "$tag-bacnet" --network "$tag" --ip "$net.13" mustra-netsurvey-bacnet \
  python /device.py --name simdev --instance 4711 --address "$net.13/24" --vendoridentifier 999 >/dev/null
docker run -d --name "$tag-enip" --network "$tag" --ip "$net.14" mustra-netsurvey-enip >/dev/null
docker run -d --name "$tag-ipp" --network "$tag" --ip "$net.15" mustra-netsurvey-ipp >/dev/null
sleep 5

(cd "$root" && CGO_ENABLED=0 go test -c -o "$work/netsurvey.test" ./internal/agent/netsurvey/)
mkdir -p "$work/capture" && chmod 777 "$work/capture"
docker run --rm --name "$tag-tester" --network "$tag" --ip "$net.10" -v "$work:/w" --entrypoint /w/netsurvey.test \
  -e MUSTRA_NETSURVEY_SIM="$net.0/24" \
  -e MUSTRA_NETSURVEY_SIM_HOSTS="snmp=$net.11,modbus=$net.12,bacnet=$net.13,enip=$net.14,ipp=$net.15" \
  -e MUSTRA_NETSURVEY_CAPTURE="${NETSURVEY_CAPTURE:+/w/capture}" \
  mustra-netsurvey-snmpd -test.run TestSimulators -test.v
if [ -n "${NETSURVEY_CAPTURE:-}" ]; then
  cp "$work"/capture/*.bin "$root/internal/agent/netsurvey/testdata/"
  python3 - "$work/capture/ipp_get_printer_attributes.http" "$root/internal/agent/netsurvey/testdata/ipp_get_printer_attributes.bin" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
open(sys.argv[2], 'wb').write(d[d.index(b'\r\n\r\n') + 4:])
PY
fi
