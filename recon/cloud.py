"""
Cloud Enumeration Module
Discover cloud assets via AWS, Azure, and GCP APIs
Supports LocalStack for simulated AWS environments via AWS_ENDPOINT_URL
"""

import subprocess
import json
import os
import shutil
from typing import List, Dict


def cloud_enumerate(provider: str = "all") -> List[Dict]:
    """
    Enumerate cloud assets from specified provider(s)

    Args:
        provider: Cloud provider to query (aws, azure, gcp, or all)

    Returns:
        List of cloud asset dictionaries
    """
    assets = []

    if provider in ["aws", "all"]:
        endpoint = os.environ.get("AWS_ENDPOINT_URL")
        if endpoint:
            print(f"[*] Enumerating AWS assets via LocalStack ({endpoint})...")
        else:
            print("[*] Enumerating AWS assets...")
        assets.extend(enumerate_aws())

    if provider in ["azure", "all"]:
        print("[*] Enumerating Azure assets...")
        assets.extend(enumerate_azure())

    if provider in ["gcp", "all"]:
        print("[*] Enumerating GCP assets...")
        assets.extend(enumerate_gcp())

    return assets


def _aws_cmd(base_cmd: List[str]) -> List[str]:
    """Prepend --endpoint-url if AWS_ENDPOINT_URL is set (for LocalStack)"""
    endpoint = os.environ.get("AWS_ENDPOINT_URL")
    if endpoint:
        return [base_cmd[0], "--endpoint-url", endpoint] + base_cmd[1:]
    return base_cmd


def enumerate_aws() -> List[Dict]:
    """Enumerate AWS EC2, S3, and RDS instances (supports LocalStack via AWS_ENDPOINT_URL)"""
    assets = []

    if not shutil.which("aws"):
        print("[!] AWS CLI not found - install with: pip install awscli")
        return assets

    try:
        result = subprocess.run(
            _aws_cmd(["aws", "sts", "get-caller-identity"]),
            capture_output=True,
            text=True,
            timeout=10,
            env=os.environ
        )

        if result.returncode != 0:
            print("[!] AWS CLI not configured - skipping AWS enumeration")
            return assets

        print("  [*] Querying EC2 instances...")
        ec2_result = subprocess.run(
            _aws_cmd(["aws", "ec2", "describe-instances", "--output", "json"]),
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ
        )

        if ec2_result.returncode == 0:
            data = json.loads(ec2_result.stdout)

            for reservation in data.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    tags = _aws_tags(instance.get('Tags', []))
                    name = tags.get("Name") or instance.get('InstanceId')
                    az = instance.get('Placement', {}).get('AvailabilityZone')
                    asset = {
                        'source': 'aws_ec2',
                        'cloud_provider': 'aws',
                        'resource_type': 'vm',
                        'resource_id': instance.get('InstanceId'),
                        'name': name,
                        'region': az[:-1] if az else None,
                        'instance_id': instance.get('InstanceId'),
                        'instance_type': instance.get('InstanceType'),
                        'state': instance.get('State', {}).get('Name'),
                        'ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'private_ip': instance.get('PrivateIpAddress'),
                        'ports': [],
                        'services': [],
                        'tags': tags,
                    }
                    assets.append(asset)

        # Enumerate S3 buckets
        print("  [*] Querying S3 buckets...")
        s3_result = subprocess.run(
            _aws_cmd(["aws", "s3api", "list-buckets", "--output", "json"]),
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ
        )

        if s3_result.returncode == 0:
            data = json.loads(s3_result.stdout)

            for bucket in data.get('Buckets', []):
                asset = {
                    'source': 'aws_s3',
                    'cloud_provider': 'aws',
                    'resource_type': 'storage',
                    'resource_id': bucket.get('Name'),
                    'name': bucket.get('Name'),
                    'region': None,
                    'bucket_name': bucket.get('Name'),
                    'created': bucket.get('CreationDate'),
                    'ip': None,
                    'public_ip': None,
                    'ports': [],
                    'services': ['s3'],
                    'tags': {},
                }
                assets.append(asset)

        # Enumerate RDS instances
        print("  [*] Querying RDS instances...")
        rds_result = subprocess.run(
            _aws_cmd(["aws", "rds", "describe-db-instances", "--output", "json"]),
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ
        )

        if rds_result.returncode == 0:
            data = json.loads(rds_result.stdout)

            for db in data.get('DBInstances', []):
                endpoint = db.get('Endpoint', {}) or {}
                port = endpoint.get('Port')
                asset = {
                    'source': 'aws_rds',
                    'cloud_provider': 'aws',
                    'resource_type': 'database',
                    'resource_id': db.get('DBInstanceArn') or db.get('DBInstanceIdentifier'),
                    'name': db.get('DBInstanceIdentifier'),
                    'region': db.get('AvailabilityZone', '')[:-1] if db.get('AvailabilityZone') else None,
                    'db_identifier': db.get('DBInstanceIdentifier'),
                    'engine': db.get('Engine'),
                    'status': db.get('DBInstanceStatus'),
                    'endpoint': endpoint.get('Address'),
                    'port': port,
                    'ip': None,
                    'public_ip': None,
                    'ports': [{'port': str(port), 'protocol': 'tcp'}] if port else [],
                    'services': [db.get('Engine')] if db.get('Engine') else [],
                    'tags': {},
                }
                assets.append(asset)

        print("  [*] Querying EC2 security groups...")
        sg_result = subprocess.run(
            _aws_cmd(["aws", "ec2", "describe-security-groups", "--output", "json"]),
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ
        )

        if sg_result.returncode == 0:
            data = json.loads(sg_result.stdout)
            for group in data.get('SecurityGroups', []):
                group_id = group.get('GroupId')
                assets.append({
                    'source': 'aws_security_group',
                    'cloud_provider': 'aws',
                    'resource_type': 'security_group',
                    'resource_id': group_id,
                    'name': group.get('GroupName') or group_id,
                    'region': None,
                    'ip': None,
                    'public_ip': None,
                    'description': group.get('Description'),
                    'vpc_id': group.get('VpcId'),
                    'ingress_rules': group.get('IpPermissions', []),
                    'egress_rules': group.get('IpPermissionsEgress', []),
                    'ports': [],
                    'services': ['security_group'],
                    'tags': _aws_tags(group.get('Tags', [])),
                })

    except subprocess.TimeoutExpired:
        print("[!] AWS API timeout")
    except Exception as e:
        print(f"[!] AWS enumeration failed: {e}")

    return assets


def enumerate_azure() -> List[Dict]:
    """Enumerate Azure VMs, public IPs, NICs, NSGs, and Storage."""
    assets = []

    if not shutil.which("az"):
        print("[!] Azure CLI not found - install from: https://aka.ms/installazurecliwindows")
        return assets
    
    try:
        # Check if Azure CLI is available
        result = subprocess.run(
            ["az", "account", "show"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            print("[!] Azure CLI not configured - skipping Azure enumeration")
            return assets
        
        # Enumerate VMs
        print("  [*] Querying Azure VMs...")
        vm_result = subprocess.run(
            ["az", "vm", "list", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if vm_result.returncode == 0:
            vms = json.loads(vm_result.stdout)
            vm_ip_details = _azure_vm_ip_details_map()
            nic_details = _azure_nic_details_map()
            
            for vm in vms:
                vm_id = vm.get('id')
                name = vm.get('name')
                resource_group = vm.get('resourceGroup')
                tags = vm.get('tags') or {}
                ip_detail = vm_ip_details.get((resource_group, name), {})
                private_ip = ip_detail.get('private_ip') or _first_azure_private_ip(vm)
                public_ip = ip_detail.get('public_ip')
                nic_ids = [
                    nic.get('id')
                    for nic in vm.get('networkProfile', {}).get('networkInterfaces', []) or []
                    if nic.get('id')
                ]
                vm_nics = [nic_details[nic_id] for nic_id in nic_ids if nic_id in nic_details]
                nsg_ids = sorted({
                    nic.get('network_security_group_id')
                    for nic in vm_nics
                    if nic.get('network_security_group_id')
                })
                image = vm.get('storageProfile', {}).get('imageReference', {}) or {}
                asset = {
                    'source': 'azure_vm',
                    'cloud_provider': 'azure',
                    'resource_type': 'vm',
                    'resource_id': vm_id,
                    'name': name,
                    'region': vm.get('location'),
                    'vm_name': vm.get('name'),
                    'vm_size': vm.get('hardwareProfile', {}).get('vmSize'),
                    'location': vm.get('location'),
                    'resource_group': resource_group,
                    'ip': private_ip,
                    'public_ip': public_ip,
                    'private_ip': private_ip,
                    'power_state': vm.get('powerState'),
                    'os_type': vm.get('storageProfile', {}).get('osDisk', {}).get('osType'),
                    'image': {
                        'publisher': image.get('publisher'),
                        'offer': image.get('offer'),
                        'sku': image.get('sku'),
                        'version': image.get('version'),
                    },
                    'network_interfaces': vm_nics,
                    'network_security_group_ids': nsg_ids,
                    'ports': [],
                    'services': [],
                    'tags': tags,
                }
                assets.append(asset)

        print("  [*] Querying Azure Network Interfaces...")
        nic_assets = _azure_nic_assets()
        assets.extend(nic_assets)
        
        # Enumerate Storage Accounts
        print("  [*] Querying Azure Storage...")
        storage_result = subprocess.run(
            ["az", "storage", "account", "list", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if storage_result.returncode == 0:
            accounts = json.loads(storage_result.stdout)
            
            for account in accounts:
                account_id = account.get('id')
                name = account.get('name')
                asset = {
                    'source': 'azure_storage',
                    'cloud_provider': 'azure',
                    'resource_type': 'storage',
                    'resource_id': account_id,
                    'name': name,
                    'region': account.get('location'),
                    'account_name': account.get('name'),
                    'location': account.get('location'),
                    'resource_group': account.get('resourceGroup'),
                    'ip': None,
                    'public_ip': None,
                    'ports': [],
                    'services': ['blob_storage'],
                    'tags': account.get('tags') or {},
                }
                assets.append(asset)

        print("  [*] Querying Azure Public IPs...")
        public_ip_result = subprocess.run(
            ["az", "network", "public-ip", "list", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if public_ip_result.returncode == 0:
            public_ips = json.loads(public_ip_result.stdout)
            for public_ip in public_ips:
                address = public_ip.get('ipAddress')
                name = public_ip.get('name')
                assets.append({
                    'source': 'azure_public_ip',
                    'cloud_provider': 'azure',
                    'resource_type': 'public_ip',
                    'resource_id': public_ip.get('id'),
                    'name': name,
                    'region': public_ip.get('location'),
                    'ip': address,
                    'public_ip': address,
                    'resource_group': public_ip.get('resourceGroup'),
                    'ports': [],
                    'services': ['public_ip'],
                    'tags': public_ip.get('tags') or {},
                })

        print("  [*] Querying Azure Network Security Groups...")
        nsg_result = subprocess.run(
            ["az", "network", "nsg", "list", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if nsg_result.returncode == 0:
            nsgs = json.loads(nsg_result.stdout)
            for nsg in nsgs:
                assets.append({
                    'source': 'azure_nsg',
                    'cloud_provider': 'azure',
                    'resource_type': 'security_group',
                    'resource_id': nsg.get('id'),
                    'name': nsg.get('name'),
                    'region': nsg.get('location'),
                    'ip': None,
                    'public_ip': None,
                    'resource_group': nsg.get('resourceGroup'),
                    'security_rules': nsg.get('securityRules', []),
                    'ports': [],
                    'services': ['network_security_group'],
                    'tags': nsg.get('tags') or {},
                })
    
    except subprocess.TimeoutExpired:
        print("[!] Azure API timeout")
    except Exception as e:
        print(f"[!] Azure enumeration failed: {e}")
    
    return assets


def _aws_tags(tags: List[Dict]) -> Dict:
    return {tag.get('Key'): tag.get('Value') for tag in tags if tag.get('Key')}


def _first_azure_private_ip(vm: Dict):
    interfaces = vm.get('networkProfile', {}).get('networkInterfaces', []) or []
    for interface in interfaces:
        ip_configs = interface.get('ipConfigurations') or []
        for config in ip_configs:
            private_ip = config.get('privateIpAddress')
            if private_ip:
                return private_ip
    return None


def _azure_vm_ip_details_map() -> Dict:
    """Return {(resource_group, vm_name): {public_ip, private_ip}} from Azure's VM IP view."""
    try:
        result = subprocess.run(
            ["az", "vm", "list-ip-addresses", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {}
        data = json.loads(result.stdout)
    except Exception:
        return {}

    mapping = {}
    if not isinstance(data, list):
        return mapping

    for item in data:
        vm = item.get("virtualMachine") or {}
        name = vm.get("name") or item.get("name")
        resource_group = vm.get("resourceGroup") or item.get("resourceGroup")
        network = vm.get("network") or item.get("network") or {}
        public_ips = network.get("publicIpAddresses") or []
        private_ips = network.get("privateIpAddresses") or []
        if name and resource_group:
            details = {}
            if private_ips:
                details["private_ip"] = private_ips[0]
            if public_ips:
                address = public_ips[0].get("ipAddress") if isinstance(public_ips[0], dict) else public_ips[0]
                if address:
                    details["public_ip"] = address
            if details:
                mapping[(resource_group, name)] = details
    return mapping


def _azure_nic_details_map() -> Dict:
    details = {}
    try:
        result = subprocess.run(
            ["az", "network", "nic", "list", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return details
        nics = json.loads(result.stdout)
    except Exception:
        return details

    for nic in nics if isinstance(nics, list) else []:
        nic_id = nic.get('id')
        if not nic_id:
            continue
        ip_configs = nic.get('ipConfigurations') or []
        private_ips = [
            cfg.get('privateIPAddress') or cfg.get('privateIpAddress')
            for cfg in ip_configs
            if cfg.get('privateIPAddress') or cfg.get('privateIpAddress')
        ]
        public_ip_ids = [
            (cfg.get('publicIPAddress') or {}).get('id')
            for cfg in ip_configs
            if (cfg.get('publicIPAddress') or {}).get('id')
        ]
        nsg = nic.get('networkSecurityGroup') or {}
        details[nic_id] = {
            'id': nic_id,
            'name': nic.get('name'),
            'resource_group': nic.get('resourceGroup'),
            'location': nic.get('location'),
            'private_ips': private_ips,
            'public_ip_ids': public_ip_ids,
            'network_security_group_id': nsg.get('id'),
            'mac_address': nic.get('macAddress'),
            'tags': nic.get('tags') or {},
        }
    return details


def _azure_nic_assets() -> List[Dict]:
    assets = []
    for nic in _azure_nic_details_map().values():
        assets.append({
            'source': 'azure_nic',
            'cloud_provider': 'azure',
            'resource_type': 'network_interface',
            'resource_id': nic.get('id'),
            'name': nic.get('name'),
            'region': nic.get('location'),
            'resource_group': nic.get('resource_group'),
            'ip': (nic.get('private_ips') or [None])[0],
            'public_ip': None,
            'private_ips': nic.get('private_ips', []),
            'public_ip_ids': nic.get('public_ip_ids', []),
            'network_security_group_id': nic.get('network_security_group_id'),
            'mac_address': nic.get('mac_address'),
            'ports': [],
            'services': ['network_interface'],
            'tags': nic.get('tags') or {},
        })
    return assets


def enumerate_gcp() -> List[Dict]:
    """Enumerate GCP Compute Engine instances"""
    assets = []

    if not shutil.which("gcloud"):
        print("[!] GCP CLI not found - install from: https://cloud.google.com/sdk/docs/install")
        return assets
    
    try:
        # Check if gcloud is available
        result = subprocess.run(
            ["gcloud", "config", "list"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            print("[!] GCP CLI not configured - skipping GCP enumeration")
            return assets
        
        # Enumerate Compute instances
        print("  [*] Querying GCP Compute instances...")
        compute_result = subprocess.run(
            ["gcloud", "compute", "instances", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if compute_result.returncode == 0:
            instances = json.loads(compute_result.stdout)
            
            for instance in instances:
                # Extract IPs from network interfaces
                ips = []
                for interface in instance.get('networkInterfaces', []):
                    ips.append(interface.get('networkIP'))
                
                asset = {
                    'source': 'gcp_compute',
                    'cloud_provider': 'gcp',
                    'resource_type': 'compute',
                    'instance_name': instance.get('name'),
                    'machine_type': instance.get('machineType', '').split('/')[-1],
                    'zone': instance.get('zone', '').split('/')[-1],
                    'status': instance.get('status'),
                    'ip': ips[0] if ips else None,
                    'ports': [],
                    'services': []
                }
                assets.append(asset)
    
    except subprocess.TimeoutExpired:
        print("[!] GCP API timeout")
    except Exception as e:
        print(f"[!] GCP enumeration failed: {e}")
    
    return assets
