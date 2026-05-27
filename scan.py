import asyncio
import bleak

async def main():
    try:
        device = await bleak.BleakScanner.find_device_by_address("98:A3:16:24:AC:DA", timeout=10.0)
        if not device:
            print("Device not found")
            return
            
        async with bleak.BleakClient(device) as client:
            print(f"Connected: {client.is_connected}")
            for service in client.services:
                print(f"Service: {service.uuid}")
                for char in service.characteristics:
                    print(f"  Char: {char.uuid} (Props: {char.properties})")
    except Exception as e:
        print(f"Error: {e}")

asyncio.run(main())
