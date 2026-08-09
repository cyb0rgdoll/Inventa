"""
Banner Grabbing Module
Service banner identification on open ports
"""

import asyncio
from typing import List, Dict


def banner_grabbing(assets: List[Dict]) -> List[Dict]:
    """
    Grab service banners from open ports on discovered assets

    Args:
        assets: List of asset dictionaries with port information

    Returns:
        Assets with added 'banners' field containing grabbed banners
    """
    return asyncio.run(_banner_grabbing_async(assets))


async def _banner_grabbing_async(assets: List[Dict]) -> List[Dict]:
    tasks = []
    for asset in assets:
        ip = asset.get('ip')
        if not ip:
            continue
        for port_info in asset.get('ports', []):
            port_num = port_info.get('port')
            if not port_num:
                continue
            try:
                port_int = int(port_num)
                tasks.append(_grab_one(asset, ip, port_num, port_int))
            except ValueError:
                continue

    await asyncio.gather(*tasks, return_exceptions=True)
    return assets


async def _grab_one(asset: Dict, ip: str, port_num: str, port_int: int):
    banner = await grab_banner_async(ip, port_int)
    if banner:
        if 'banners' not in asset:
            asset['banners'] = []
        asset['banners'].append({'port': port_num, 'banner': banner})
        print(f"  [+] {ip}:{port_num} → {banner[:60]}...")


async def grab_banner_async(ip: str, port: int, timeout: int = 3) -> str:
    """Async banner grab for a single IP:port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )

        if port in [80, 443, 8080, 8443]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port in [25, 587]:
            writer.write(b"HELO inventa\r\n")

        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = data.decode('utf-8', errors='ignore').strip()
        except asyncio.TimeoutError:
            banner = None

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return banner if banner else None

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


def grab_banner(ip: str, port: int, timeout: int = 3) -> str:
    """
    Attempt to grab a service banner from a specific IP:port

    Args:
        ip: Target IP address
        port: Target port number
        timeout: Connection timeout in seconds

    Returns:
        Banner string if successful, None otherwise
    """
    return asyncio.run(grab_banner_async(ip, port, timeout))
