# A BACnet/IP device from bacpypes3; it answers Who-Is with I-Am.
import asyncio
from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.app import Application
async def main():
    args = SimpleArgumentParser().parse_args()
    app = Application.from_args(args)
    await asyncio.Future()
asyncio.run(main())
