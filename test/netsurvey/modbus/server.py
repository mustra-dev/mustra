# A Modbus TCP server from pymodbus with device identification set; the
# survey reads only function 43/14 from it.
import logging
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
logging.basicConfig(level=logging.INFO)
store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0]*10))
ctx = ModbusServerContext(slaves=store, single=True)
ident = ModbusDeviceIdentification(info_name={
    "VendorName": "Acme Automation",
    "ProductCode": "AC-PLC-200",
    "MajorMinorRevision": "4.2.1",
    "VendorUrl": "http://example.invalid",
    "ProductName": "Acme PLC",
    "ModelName": "PLC-200",
    "UserApplicationName": "line-3-controller",
})
StartTcpServer(context=ctx, identity=ident, address=("0.0.0.0", 502))
