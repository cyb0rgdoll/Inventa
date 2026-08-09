"""
Device Identification Module
Identify non-agent-capable assets (printers, IoT, network devices)
"""

from typing import List, Dict
import re

# Compile patterns once at module load to avoid repeated recompilation per asset
_PRINTER_HOSTNAME = re.compile(r'printer|laserjet|officejet|canon|epson|xerox', re.I)
_PRINTER_BANNER = re.compile(r'printer|laserjet|hp |canon|epson', re.I)
_NETWORK_HOSTNAME = re.compile(r'switch|router|gateway|\bfw\b|firewall|cisco|juniper', re.I)
_NETWORK_BANNER = re.compile(r'cisco|juniper|mikrotik|ubiquiti|netgear', re.I)
_CAMERA_HOSTNAME = re.compile(r'camera|cam|ipcam|nvr|dvr|cctv', re.I)
_CAMERA_BANNER = re.compile(r'hikvision|dahua|axis|camera|rtsp', re.I)
_IOT_HOSTNAME = re.compile(r'iot|sensor|temp|humidity|motion', re.I)
_VOIP_HOSTNAME = re.compile(r'phone|voip|polycom|cisco|yealink', re.I)
_VOIP_BANNER = re.compile(r'polycom|yealink|cisco|sip|grandstream', re.I)
_BUILDING_HOSTNAME = re.compile(r'hvac|bms|scada|automation|thermostat', re.I)
_NAS_HOSTNAME = re.compile(r'nas|storage|synology|qnap|netapp', re.I)
_AP_HOSTNAME = re.compile(r'\bap\b|wap|wireless|wifi|ubiquiti|aruba', re.I)


def identify_devices(assets: List[Dict]) -> List[Dict]:
    """
    Enhance device identification for non-agent-capable assets

    Args:
        assets: List of asset dictionaries

    Returns:
        Assets with improved device type classification
    """
    for asset in assets:
        current_type = asset.get('asset_type', '')
        if current_type not in ['Unknown Host', 'Unclassified', None, '']:
            continue

        device_type = classify_non_standard_device(asset)

        if device_type:
            asset['asset_type'] = device_type
            asset['non_agent_capable'] = True

    return assets


def classify_non_standard_device(asset: Dict) -> str:
    """
    Classify non-standard devices using multiple signals

    Args:
        asset: Asset dictionary

    Returns:
        Device type string if identified, None otherwise
    """
    hostname = (asset.get('hostname') or '').lower()
    services = asset.get('services', [])
    ports = [p.get('port') for p in asset.get('ports', [])]
    banners = asset.get('banners', [])
    os_info = (asset.get('os') or '').lower()

    if is_printer(hostname, services, ports, banners):
        return "Network Printer"

    if is_network_device(hostname, services, ports, banners):
        return "Network Infrastructure"

    if is_ip_camera(hostname, services, ports, banners):
        return "IP Camera"

    if is_iot_sensor(hostname, services, ports):
        return "IoT Sensor"

    if is_voip_phone(hostname, services, ports, banners):
        return "VoIP Phone"

    if is_building_automation(hostname, services, ports):
        return "Building Automation"

    if is_nas(hostname, services, ports):
        return "Network Attached Storage"

    if is_wireless_ap(hostname, services, ports):
        return "Wireless Access Point"

    return None


def _banner_texts(banners: List) -> List[str]:
    return [(b.get('banner') or '').lower() for b in banners]


def is_printer(hostname: str, services: List, ports: List, banners: List) -> bool:
    """Identify network printers"""
    printer_indicators = [
        bool(_PRINTER_HOSTNAME.search(hostname)),
        '631' in ports,
        '9100' in ports,
        'ipp' in services,
        'lpd' in services,
    ]

    for text in _banner_texts(banners):
        if _PRINTER_BANNER.search(text):
            printer_indicators.append(True)

    return sum(printer_indicators) >= 2


def is_network_device(hostname: str, services: List, ports: List, banners: List) -> bool:
    """Identify network switches, routers, firewalls"""
    network_indicators = [
        bool(_NETWORK_HOSTNAME.search(hostname)),
        '23' in ports and '22' in ports,
        '161' in ports,
        'snmp' in services,
    ]

    for text in _banner_texts(banners):
        if _NETWORK_BANNER.search(text):
            network_indicators.append(True)

    return sum(network_indicators) >= 2


def is_ip_camera(hostname: str, services: List, ports: List, banners: List) -> bool:
    """Identify IP cameras and DVR/NVR systems"""
    camera_indicators = [
        bool(_CAMERA_HOSTNAME.search(hostname)),
        '554' in ports,
        '8000' in ports,
        'rtsp' in services,
    ]

    for text in _banner_texts(banners):
        if _CAMERA_BANNER.search(text):
            camera_indicators.append(True)

    return sum(camera_indicators) >= 2


def is_iot_sensor(hostname: str, services: List, ports: List) -> bool:
    """Identify IoT sensors"""
    iot_indicators = [
        bool(_IOT_HOSTNAME.search(hostname)),
        '1883' in ports,
        '8883' in ports,
        'mqtt' in services,
        'coap' in services,
    ]

    return sum(iot_indicators) >= 2


def is_voip_phone(hostname: str, services: List, ports: List, banners: List) -> bool:
    """Identify VoIP phones"""
    voip_indicators = [
        bool(_VOIP_HOSTNAME.search(hostname)),
        '5060' in ports,
        '5061' in ports,
        'sip' in services,
    ]

    for text in _banner_texts(banners):
        if _VOIP_BANNER.search(text):
            voip_indicators.append(True)

    return sum(voip_indicators) >= 2


def is_building_automation(hostname: str, services: List, ports: List) -> bool:
    """Identify building automation/HVAC systems"""
    automation_indicators = [
        bool(_BUILDING_HOSTNAME.search(hostname)),
        '502' in ports,
        '47808' in ports,
        'modbus' in services,
        'bacnet' in services,
    ]

    return sum(automation_indicators) >= 2


def is_nas(hostname: str, services: List, ports: List) -> bool:
    """Identify network attached storage"""
    nas_indicators = [
        bool(_NAS_HOSTNAME.search(hostname)),
        'nfs' in services,
        'smb' in services and 'cifs' in services,
        '2049' in ports,
        set(['139', '445']).issubset(set(ports)),
    ]

    return sum(nas_indicators) >= 2


def is_wireless_ap(hostname: str, services: List, ports: List) -> bool:
    """Identify wireless access points"""
    ap_indicators = [
        bool(_AP_HOSTNAME.search(hostname)),
        '10001' in ports,
        '8443' in ports and '22' in ports,
    ]

    return sum(ap_indicators) >= 2
