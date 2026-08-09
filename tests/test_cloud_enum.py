from modules import cloud_enum


def test_cloud_enumerate_missing_clis_returns_empty(monkeypatch, capsys):
    monkeypatch.setattr(cloud_enum.shutil, "which", lambda name: None)

    assets = cloud_enum.cloud_enumerate()

    output = capsys.readouterr().out
    assert assets == []
    assert "AWS CLI not found" in output
    assert "Azure CLI not found" in output
    assert "GCP CLI not found" in output


def test_aws_assets_use_normalized_cloud_fields(monkeypatch):
    monkeypatch.setattr(cloud_enum.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "aws" else None)

    def fake_run(cmd, **kwargs):
        class Result:
            returncode = 0
            stdout = "{}"
            stderr = ""

        result = Result()
        joined = " ".join(cmd)
        if "get-caller-identity" in joined:
            result.stdout = '{"Account":"123456789012"}'
        elif "describe-instances" in joined:
            result.stdout = '{"Reservations":[{"Instances":[{"InstanceId":"i-123","InstanceType":"t3.micro","State":{"Name":"running"},"PrivateIpAddress":"10.0.0.5","PublicIpAddress":"198.51.100.5","Placement":{"AvailabilityZone":"ap-southeast-2a"},"Tags":[{"Key":"Name","Value":"web-1"}]}]}]}'
        elif "list-buckets" in joined:
            result.stdout = '{"Buckets":[{"Name":"asset-bucket","CreationDate":"2026-01-01T00:00:00Z"}]}'
        elif "describe-db-instances" in joined:
            result.stdout = '{"DBInstances":[{"DBInstanceIdentifier":"db-1","DBInstanceArn":"arn:db","Engine":"postgres","DBInstanceStatus":"available","Endpoint":{"Address":"db.example","Port":5432},"AvailabilityZone":"ap-southeast-2a"}]}'
        elif "describe-security-groups" in joined:
            result.stdout = '{"SecurityGroups":[{"GroupId":"sg-123","GroupName":"web-sg","Description":"web","VpcId":"vpc-1","IpPermissions":[],"IpPermissionsEgress":[],"Tags":[]}]}'
        return result

    monkeypatch.setattr(cloud_enum.subprocess, "run", fake_run)

    assets = cloud_enum.enumerate_aws()
    by_type = {asset["resource_type"]: asset for asset in assets}

    assert by_type["vm"]["resource_id"] == "i-123"
    assert by_type["vm"]["name"] == "web-1"
    assert by_type["vm"]["region"] == "ap-southeast-2"
    assert by_type["storage"]["name"] == "asset-bucket"
    assert by_type["database"]["ports"][0]["port"] == "5432"
    assert by_type["security_group"]["resource_id"] == "sg-123"


def test_azure_assets_use_normalized_cloud_fields(monkeypatch):
    monkeypatch.setattr(cloud_enum.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "az" else None)

    def fake_run(cmd, **kwargs):
        class Result:
            returncode = 0
            stdout = "{}"
            stderr = ""

        result = Result()
        joined = " ".join(cmd)
        if "account show" in joined:
            result.stdout = '{"id":"sub-1"}'
        elif "vm list-ip-addresses" in joined:
            result.stdout = '[{"virtualMachine":{"name":"vm-1","resourceGroup":"rg-1","network":{"publicIpAddresses":[{"ipAddress":"203.0.113.9"}]}}}]'
        elif "vm list" in joined:
            result.stdout = '[{"id":"/vm/1","name":"vm-1","location":"australiaeast","resourceGroup":"rg-1","hardwareProfile":{"vmSize":"Standard_B1s"},"networkProfile":{"networkInterfaces":[{"ipConfigurations":[{"privateIpAddress":"10.1.0.4"}]}]},"tags":{"env":"lab"}}]'
        elif "public-ip list" in joined:
            result.stdout = '[{"id":"/pip/1","name":"pip-1","location":"australiaeast","resourceGroup":"rg-1","ipAddress":"203.0.113.8","tags":{}}]'
        elif "nsg list" in joined:
            result.stdout = '[{"id":"/nsg/1","name":"nsg-1","location":"australiaeast","resourceGroup":"rg-1","securityRules":[],"tags":{}}]'
        elif "storage account list" in joined:
            result.stdout = '[{"id":"/storage/1","name":"store1","location":"australiaeast","resourceGroup":"rg-1","tags":{}}]'
        return result

    monkeypatch.setattr(cloud_enum.subprocess, "run", fake_run)

    assets = cloud_enum.enumerate_azure()
    by_source = {asset["source"]: asset for asset in assets}

    assert by_source["azure_vm"]["resource_id"] == "/vm/1"
    assert by_source["azure_vm"]["name"] == "vm-1"
    assert by_source["azure_vm"]["ip"] == "10.1.0.4"
    assert by_source["azure_vm"]["public_ip"] == "203.0.113.9"
    assert by_source["azure_public_ip"]["public_ip"] == "203.0.113.8"
    assert by_source["azure_nsg"]["resource_type"] == "security_group"
