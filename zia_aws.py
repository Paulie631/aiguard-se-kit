"""CloudFormation template for the ZIA traffic generator on AWS.

`aiguard-kit zia aws` writes a template filled in for your tenant (cloud, user domain, test user). You upload it in
the CloudFormation console: no AWS CLI or AWS keys on your laptop. One stack holds everything; deleting the stack
removes it all.

The stack: its own small VPC (or an existing subnet), a security group with no inbound ports, an SSM role (connect
through Fleet Manager remote desktop, nothing exposed), one Windows Server 2022 instance whose first-boot script
installs Client Connector (from a URL you give, optional), uv and the kit, and two scheduled tasks: a traffic round
every N minutes (only once traffic is confirmed to go through Zscaler) and `zia check` at startup. Optionally a
weekday start / nightly stop to keep costs down.

No secrets are in the template: you sign in to Client Connector once, by hand, as the test user.
"""
from __future__ import annotations

import json

# The newest ZIA kit release (a rolling copy on the zia-latest release). Override with the KitZipUrl parameter.
KIT_ZIP = "https://github.com/Paulie631/aiguard-se-kit/releases/download/zia-latest/zscaler-zia-kit.zip"
# The Client Connector installer the kit offers by default: a copy of Zscaler's Windows installer attached to the
# zcc-installer release (a pre-release, so the kit's update check never sees it). The instance installs it only if
# its SHA-256 matches and it carries a valid Zscaler code signature. To change versions: attach the new file to that
# release and update all three values here. Empty url: no default, SEs install by hand or give their own.
ZCC_DEFAULT = {"version": "4.10.0.477",
               "url": "https://github.com/Paulie631/aiguard-se-kit/releases/download/zcc-installer/"
                      "Zscaler-windows-4.10.0.477-installer.msi",
               "sha256": "793fc24713c26e0d6ac5a9f0371d844d438972f5f68c4e05c531d02948eba2ef"}
AMI_PARAM = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
NAME = "SE-Demo ZIA traffic generator"

# First-boot script (EC2Launch runs it as SYSTEM). ${...} are CloudFormation parameters; PowerShell variables
# deliberately never use braces so Fn::Sub leaves them alone.
USER_DATA = r"""<powershell>
$ErrorActionPreference = "Continue"
$root = "C:\SE-Demo"
New-Item -ItemType Directory -Force -Path $root, "$root\home" | Out-Null
Start-Transcript -Path "$root\setup.log" -Append
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
"SE-Demo ZIA traffic generator: first-boot setup for test user ${TestUser}"

# 1. Zscaler Client Connector (optional: without an installer, install it by hand)
$zcc = "${ZccInstallerUrl}"
$s3o = "${ZccS3Object}"
if ($zcc -or $s3o) {
  $ext = "msi"
  if (($zcc + $s3o) -match "\.exe(\?|$)") { $ext = "exe" }
  $f = "$root\zcc-installer.$ext"
  $want = "${ZccInstallerSha256}"
  if ($s3o) {
    # Your own bucket: the instance role may read only this one object, so there's no link to expire or leak.
    $b, $k = $s3o.Split("/", 2)
    Read-S3Object -BucketName $b -Key $k -File $f -Region "${AWS::Region}" | Out-Null
  } else {
    Invoke-WebRequest -Uri $zcc -OutFile $f -UseBasicParsing
  }
  # Never run a file that isn't Zscaler's: check the pinned SHA-256 (when given) and the code signature.
  $ok = Test-Path $f
  if ($ok -and $want) {
    $got = (Get-FileHash $f -Algorithm SHA256).Hash
    if ($got -ne $want.ToUpper()) { "Client Connector installer SHA-256 is $got, expected $want. Not installing it."; $ok = $false }
  }
  if ($ok) {
    $sig = Get-AuthenticodeSignature $f
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Zscaler") {
      "Client Connector installer isn't validly signed by Zscaler (" + $sig.Status + "): not installing it."; $ok = $false
    }
  }
  # The policy token makes Client Connector download the kit's app profile at install, before anyone signs in:
  # Z-Tunnel 2.0 and the Zscaler root certificate are in place from the start.
  $pt = "${ZccPolicyToken}"
  if (-not $ok) {
    "Install Client Connector by hand from your demo tenant, then sign in as ${TestUser}."
  } elseif ($ext -eq "msi") {
    $margs = "/i `"$f`" /quiet /norestart CLOUDNAME=${ZccCloudName} USERDOMAIN=${ZccUserDomain}"
    if ($pt) { $margs += " POLICYTOKEN=$pt" }
    Start-Process msiexec.exe -Wait -ArgumentList $margs
    "Client Connector installed" + $(if ($pt) { " with the kit's app profile" } else { "" }) + ". Sign in as ${TestUser}."
  } else {
    $xargs = "--mode unattended --cloudName ${ZccCloudName} --userDomain ${ZccUserDomain}"
    if ($pt) { $xargs += " --policyToken $pt" }
    Start-Process $f -Wait -ArgumentList $xargs
    "Client Connector installed" + $(if ($pt) { " with the kit's app profile" } else { "" }) + ". Sign in as ${TestUser}."
  }
} else {
  "No Client Connector installer URL given: install it by hand, then sign in as ${TestUser}."
}

# 2. uv and the kit
$env:UV_INSTALL_DIR = "$root\uv"
Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
Invoke-WebRequest -Uri "${KitZipUrl}" -OutFile "$root\kit.zip" -UseBasicParsing
Remove-Item -Recurse -Force "$root\kit", "$root\kit-extract" -ErrorAction SilentlyContinue
Expand-Archive -Force "$root\kit.zip" "$root\kit-extract"
$found = (Get-ChildItem "$root\kit-extract" -Recurse -Filter aiguard_kit.py | Select-Object -First 1).DirectoryName
Move-Item $found "$root\kit"

# 3. Wrappers: the kit runs from C:\SE-Demo with its settings and logs there too
$envs = @"
@echo off
set USERPROFILE=$root\home
set UV_CACHE_DIR=$root\uv-cache
set UV_PYTHON_INSTALL_DIR=$root\python
set UV_SYSTEM_CERTS=1
set UV_NATIVE_TLS=1
set PYTHONUTF8=1
"@
Set-Content -Encoding ascii -Path "$root\zia.cmd" -Value ($envs + "`r`nset NO_COLOR=1`r`n`"$root\uv\uv.exe`" run --quiet --python 3.12 --script `"$root\kit\aiguard_kit.py`" zia %* --yes >> `"$root\traffic.log`" 2>&1`r`n")
Set-Content -Encoding ascii -Path "$root\console.cmd" -Value ($envs + "`r`n`"$root\uv\uv.exe`" run --quiet --python 3.12 --script `"$root\kit\aiguard_kit.py`" gui`r`n")
& "$root\zia.cmd" help

# 4. Scheduled tasks (as SYSTEM, so they run with nobody signed in to Windows)
$a = New-ScheduledTaskAction -Execute "$root\zia.cmd" -Argument "traffic --count ${RequestsPerType}"
$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes ${TrafficEveryMinutes})
Register-ScheduledTask -TaskName "SE-Demo ZIA traffic" -Action $a -Trigger $t -User "SYSTEM" -RunLevel Highest -Force
$a2 = New-ScheduledTaskAction -Execute "$root\zia.cmd" -Argument "check"
Register-ScheduledTask -TaskName "SE-Demo ZIA check" -Action $a2 -Trigger (New-ScheduledTaskTrigger -AtStartup) -User "SYSTEM" -RunLevel Highest -Force

# 5. Desktop shortcuts for whoever signs in over remote desktop
$sh = New-Object -ComObject WScript.Shell
foreach ($s in @(@("SE-Demo ZIA console", "$root\console.cmd"), @("SE-Demo traffic log", "$root\traffic.log"), @("SE-Demo setup log", "$root\setup.log"))) {
  $l = $sh.CreateShortcut("C:\Users\Public\Desktop\" + $s[0] + ".lnk"); $l.TargetPath = $s[1]
  if ($s[1] -like "*console.cmd" -and (Test-Path "$root\kit\assets\zia-icon.ico")) { $l.IconLocation = "$root\kit\assets\zia-icon.ico,0" }
  $l.Save()
}
# 6. Let whoever signs in run the console too. Setup ran as SYSTEM, so C:\SE-Demo (uv cache, Python, settings)
#    is otherwise read-only to a remote desktop user's non-elevated session. This box is single-purpose and only
#    administrators can sign in to it, so giving local Users modify rights here is acceptable.
icacls $root /grant "*S-1-5-32-545:(OI)(CI)M" /T /C /Q | Out-Null
"Setup finished. Traffic starts once Client Connector is signed in as ${TestUser}."
Stop-Transcript
</powershell>
<persist>false</persist>
"""


def param(type_, default, desc, **kw):
    p = {"Type": type_, "Default": default, "Description": desc}
    p.update(kw)
    return p


def _installer(zcc_url, zcc_s3, zcc_sha256):
    if zcc_url == "none":                                   # explicitly no installer: install by hand
        return "", ""
    if not zcc_url and not zcc_s3 and ZCC_DEFAULT["url"]:    # the kit's own copy, pinned by hash
        return ZCC_DEFAULT["url"], ZCC_DEFAULT["sha256"]
    return zcc_url, zcc_sha256


def build(cloud="zscalertwo", domain="example.com", test_user="se-demo-traffic@example.com", kit_zip=KIT_ZIP,
          zcc_url="", zcc_s3="", zcc_sha256="", every=30, per_type=4, schedule=True, policy_token=""):
    zcc_url, zcc_sha256 = _installer(zcc_url, zcc_s3, zcc_sha256)
    tags = [{"Key": "Name", "Value": NAME}, {"Key": "se-demo", "Value": "zia-traffic-generator"}]
    params = {
        "TestUser": param("String", test_user, "The ZIA test user (from aiguard-kit zia setup). Sign in to Client "
                                               "Connector as this user once, over Fleet Manager remote desktop."),
        "ZccCloudName": param("String", cloud, "Your Zscaler cloud, for example zscalertwo."),
        "ZccUserDomain": param("String", domain, "Your tenant's user domain."),
        "ZccInstallerUrl": param("String", zcc_url, "Optional HTTPS URL of the Client Connector Windows installer "
                                                    "(.msi or .exe), e.g. an S3 presigned URL. Empty: install it by hand."),
        "ZccInstallerSha256": param("String", zcc_sha256, "Optional SHA-256 the installer must match (the kit fills "
                                                          "it in for its own copy). The installer must also carry a "
                                                          "valid Zscaler signature either way.",
                                    AllowedPattern=r"^$|^[A-Fa-f0-9]{64}$", ConstraintDescription="64 hex characters, or empty"),
        "ZccS3Object": param("String", zcc_s3, "Optional, instead of a URL: the Client Connector installer in your own S3 "
                                               "bucket, as bucket/key (for example my-bucket/Zscaler-windows-x64.msi), "
                                               "in this region. The instance may read only that object.",
                             AllowedPattern=r"^$|^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]/.+\.(msi|exe)$",
                             ConstraintDescription="bucket/key of an .msi or .exe, or empty"),
        "ZccPolicyToken": param("String", policy_token, "Optional: the policy token of the kit's Client Connector app "
                                "profile (the kit fills it in). Client Connector then has that profile's settings "
                                "(Z-Tunnel 2.0, Zscaler certificate) before anyone signs in. Empty: picked up at sign-in. "
                                "Not a password: Client Connector still needs the test user to sign in."),
        "KitZipUrl": param("String", kit_zip, "Where the instance downloads the kit (a GitHub zip)."),
        "TrafficEveryMinutes": param("Number", every, "Minutes between traffic rounds.", MinValue=15, MaxValue=1440),
        "RequestsPerType": param("Number", per_type, "Requests per traffic type per round.", MinValue=1, MaxValue=20),
        "InstanceType": param("String", "t3.medium", "Instance size.", AllowedValues=["t3.medium", "t3.large", "m6i.large"]),
        "WindowsAmi": param("AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>", AMI_PARAM,
                            "Latest Windows Server 2022 image (looked up at deploy time)."),
        "NetworkMode": param("String", "CreateVpc", "CreateVpc: its own VPC with direct internet access (recommended, "
                             "so no corporate inspection sits in front of Zscaler). ExistingSubnet: use the two "
                             "parameters below.", AllowedValues=["CreateVpc", "ExistingSubnet"]),
        "ExistingVpcId": param("String", "", "Only with ExistingSubnet: the VPC id."),
        "ExistingSubnetId": param("String", "", "Only with ExistingSubnet: a subnet with a direct internet route."),
        "ExistingInstanceProfile": param("String", "", "Optional: an existing instance profile with "
                                         "AmazonSSMManagedInstanceCore, if this account doesn't let stacks create IAM roles."),
        "KeyPairName": param("String", "", "Optional: an EC2 key pair, to get the Administrator password for remote desktop."),
        "WeekdaySchedule": param("String", "true" if schedule else "false", "Start the instance at 7am and stop it at "
                                 "9pm (New York time), weekdays start only. Needs IAM.", AllowedValues=["true", "false"]),
    }
    cond = {
        "CreateVpc": {"Fn::Equals": [{"Ref": "NetworkMode"}, "CreateVpc"]},
        "CreateRole": {"Fn::Equals": [{"Ref": "ExistingInstanceProfile"}, ""]},
        "HasKey": {"Fn::Not": [{"Fn::Equals": [{"Ref": "KeyPairName"}, ""]}]},
        "ReadZccFromS3": {"Fn::And": [{"Fn::Not": [{"Fn::Equals": [{"Ref": "ZccS3Object"}, ""]}]}, {"Condition": "CreateRole"}]},
        "Schedule": {"Fn::And": [{"Fn::Equals": [{"Ref": "WeekdaySchedule"}, "true"]}, {"Condition": "CreateRole"}]},
    }
    res = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Condition": "CreateVpc",
                "Properties": {"CidrBlock": "10.77.0.0/16", "EnableDnsSupport": True, "EnableDnsHostnames": True,
                               "Tags": tags}},
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Condition": "CreateVpc", "Properties": {"Tags": tags}},
        "IgwAttach": {"Type": "AWS::EC2::VPCGatewayAttachment", "Condition": "CreateVpc",
                      "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Condition": "CreateVpc",
                   "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.77.1.0/24", "MapPublicIpOnLaunch": True,
                                  "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}, "Tags": tags}},
        "RouteTable": {"Type": "AWS::EC2::RouteTable", "Condition": "CreateVpc",
                       "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": tags}},
        "DefaultRoute": {"Type": "AWS::EC2::Route", "Condition": "CreateVpc", "DependsOn": "IgwAttach",
                         "Properties": {"RouteTableId": {"Ref": "RouteTable"}, "DestinationCidrBlock": "0.0.0.0/0",
                                        "GatewayId": {"Ref": "Igw"}}},
        "SubnetRoutes": {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Condition": "CreateVpc",
                         "Properties": {"SubnetId": {"Ref": "Subnet"}, "RouteTableId": {"Ref": "RouteTable"}}},
        "NoInbound": {"Type": "AWS::EC2::SecurityGroup",
                      "Properties": {"GroupDescription": "SE-Demo generator: no inbound; connect with Fleet Manager",
                                     "VpcId": {"Fn::If": ["CreateVpc", {"Ref": "Vpc"}, {"Ref": "ExistingVpcId"}]},
                                     "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}],
                                     "Tags": tags}},
        "SsmRole": {"Type": "AWS::IAM::Role", "Condition": "CreateRole",
                    "Properties": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                        "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"}],
                        "Tags": tags}},
        "ZccInstallerRead": {"Type": "AWS::IAM::RolePolicy", "Condition": "ReadZccFromS3",
                             "Properties": {"RoleName": {"Ref": "SsmRole"}, "PolicyName": "read-client-connector-installer",
                                            "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                                                "Effect": "Allow", "Action": "s3:GetObject",
                                                "Resource": {"Fn::Sub": "arn:${AWS::Partition}:s3:::${ZccS3Object}"}}]}}},
        "SsmProfile": {"Type": "AWS::IAM::InstanceProfile", "Condition": "CreateRole",
                       "Properties": {"Roles": [{"Ref": "SsmRole"}]}},
        "Generator": {"Type": "AWS::EC2::Instance", "DependsOn": [],
                      "Properties": {
                          "ImageId": {"Ref": "WindowsAmi"}, "InstanceType": {"Ref": "InstanceType"},
                          "SubnetId": {"Fn::If": ["CreateVpc", {"Ref": "Subnet"}, {"Ref": "ExistingSubnetId"}]},
                          "SecurityGroupIds": [{"Ref": "NoInbound"}],
                          "IamInstanceProfile": {"Fn::If": ["CreateRole", {"Ref": "SsmProfile"}, {"Ref": "ExistingInstanceProfile"}]},
                          "KeyName": {"Fn::If": ["HasKey", {"Ref": "KeyPairName"}, {"Ref": "AWS::NoValue"}]},
                          "MetadataOptions": {"HttpTokens": "required"},
                          "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 60, "VolumeType": "gp3",
                                                                                       "Encrypted": True}}],
                          "UserData": {"Fn::Base64": {"Fn::Sub": USER_DATA}},
                          "Tags": tags}},
        "SchedulerRole": {"Type": "AWS::IAM::Role", "Condition": "Schedule",
                          "Properties": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                              {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                              "Policies": [{"PolicyName": "start-stop-generator", "PolicyDocument": {
                                  "Version": "2012-10-17", "Statement": [{
                                      "Effect": "Allow", "Action": ["ec2:StartInstances", "ec2:StopInstances"],
                                      "Resource": {"Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${Generator}"}}]}}],
                              "Tags": tags}},
        "MorningStart": {"Type": "AWS::Scheduler::Schedule", "Condition": "Schedule",
                         "Properties": {"Description": "SE-Demo generator: start weekdays 7am New York",
                                        "ScheduleExpression": "cron(0 7 ? * MON-FRI *)",
                                        "ScheduleExpressionTimezone": "America/New_York",
                                        "FlexibleTimeWindow": {"Mode": "OFF"},
                                        "Target": {"Arn": "arn:aws:scheduler:::aws-sdk:ec2:startInstances",
                                                   "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                                                   "Input": {"Fn::Sub": '{"InstanceIds": ["${Generator}"]}'}}}},
        "NightlyStop": {"Type": "AWS::Scheduler::Schedule", "Condition": "Schedule",
                        "Properties": {"Description": "SE-Demo generator: stop nightly 9pm New York",
                                       "ScheduleExpression": "cron(0 21 * * ? *)",
                                       "ScheduleExpressionTimezone": "America/New_York",
                                       "FlexibleTimeWindow": {"Mode": "OFF"},
                                       "Target": {"Arn": "arn:aws:scheduler:::aws-sdk:ec2:stopInstances",
                                                  "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                                                  "Input": {"Fn::Sub": '{"InstanceIds": ["${Generator}"]}'}}}},
    }
    del res["Generator"]["DependsOn"]
    out = {
        "InstanceId": {"Value": {"Ref": "Generator"}},
        "ConnectWithFleetManager": {
            "Description": "Open, then Node actions > Connect > Connect with Remote Desktop. Single sign-on is offered only "
                           "if you signed in to AWS with IAM Identity Center; otherwise choose User credentials and set an "
                           "Administrator password first (see SetAdministratorPassword).",
            "Value": {"Fn::Sub": "https://${AWS::Region}.console.aws.amazon.com/systems-manager/fleet-manager/"
                                 "managed-nodes/${Generator}/general?region=${AWS::Region}"}},
        "SetAdministratorPassword": {
            "Description": "Only if Fleet Manager offers no single sign-on: Systems Manager > Session Manager > Start "
                           "session on this instance, run this, type a password (not echoed), then Connect with Remote "
                           "Desktop > User credentials as Administrator",
            "Value": "$p = Read-Host -AsSecureString 'New password'; Set-LocalUser -Name Administrator -Password $p; "
                     "Enable-LocalUser Administrator"},
        "NextSteps": {"Value": {"Fn::Sub": "Wait about 10 minutes, connect with Fleet Manager remote desktop, sign in "
                                           "to Client Connector as ${TestUser} (password: the one the kit created, "
                                           "shown by aiguard-kit zia password on your laptop, or for a ZIdentity user "
                                           "the one you set in ZIdentity), then open 'SE-Demo traffic log' on the "
                                           "desktop."}},
    }
    return {"AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"{NAME} for {test_user} (aiguard-kit zia aws). Delete the stack to remove everything.",
            "Metadata": {"AWS::CloudFormation::Interface": {"ParameterGroups": [
                {"Label": {"default": "Zscaler"}, "Parameters": ["TestUser", "ZccCloudName", "ZccUserDomain", "ZccS3Object", "ZccInstallerUrl", "ZccInstallerSha256", "ZccPolicyToken"]},
                {"Label": {"default": "Traffic"}, "Parameters": ["TrafficEveryMinutes", "RequestsPerType", "KitZipUrl"]},
                {"Label": {"default": "AWS"}, "Parameters": ["InstanceType", "WeekdaySchedule", "NetworkMode", "ExistingVpcId",
                                                              "ExistingSubnetId", "ExistingInstanceProfile", "KeyPairName", "WindowsAmi"]}]}},
            "Parameters": params, "Conditions": cond, "Resources": res, "Outputs": out,
            "Rules": {"ExistingSubnetNeedsIds": {
                "RuleCondition": {"Fn::Equals": [{"Ref": "NetworkMode"}, "ExistingSubnet"]},
                "Assertions": [{"Assert": {"Fn::And": [
                    {"Fn::Not": [{"Fn::Equals": [{"Ref": "ExistingVpcId"}, ""]}]},
                    {"Fn::Not": [{"Fn::Equals": [{"Ref": "ExistingSubnetId"}, ""]}]}]},
                    "AssertDescription": "With NetworkMode ExistingSubnet, fill in ExistingVpcId and ExistingSubnetId."}]}}}


def write(path, **kw):
    from pathlib import Path
    Path(path).write_text(json.dumps(build(**kw), indent=2), encoding="utf-8")
    return path


SAFE_VALUE = __import__("re").compile(r"^[A-Za-z0-9._:/@?=&%+~#-]*$")


def setup_script(cloud="zscalertwo", domain="example.com", test_user="se-demo-traffic@example.com", kit_zip=KIT_ZIP,
                 zcc_url="", zcc_s3="", zcc_sha256="", every=30, per_type=4, policy_token="", **_):
    """The same first-boot setup as the AWS template, as a PowerShell script for any Windows VM with direct internet
    access (CloudShare, a lab VM, another cloud). Run it once in PowerShell as Administrator."""
    if zcc_s3:
        raise ValueError("An s3:// installer only works on AWS. Leave the installer field empty (the kit's verified "
                         "copy), give an https URL, or 'none'.")
    zcc_url, zcc_sha256 = _installer(zcc_url, zcc_s3, zcc_sha256)
    values = {"TestUser": test_user, "ZccCloudName": cloud, "ZccUserDomain": domain, "ZccInstallerUrl": zcc_url,
              "ZccS3Object": "", "ZccInstallerSha256": zcc_sha256, "ZccPolicyToken": policy_token,
              "KitZipUrl": kit_zip, "TrafficEveryMinutes": str(int(every)), "RequestsPerType": str(int(per_type)),
              "AWS::Region": ""}
    for k, v in values.items():   # every value lands inside a PowerShell string: allow plain URL/name characters only
        if not SAFE_VALUE.match(str(v)):
            raise ValueError(f"{k} has characters the setup script can't take safely: {v!r}")
    body = USER_DATA.replace("<powershell>\n", "").replace("</powershell>\n<persist>false</persist>\n", "")
    body = body.replace("first-boot setup for test user", "setup for test user")
    for k, v in values.items():
        body = body.replace("${" + k + "}", str(v))
    head = (f"# {NAME}: setup script for a Windows VM (CloudShare, a lab VM or another cloud).\n"
            f"# Made by the SE demo kit for test user {test_user}, cloud {cloud}.\n"
            "# Needs: Windows Server 2022 or Windows 10/11, direct internet access (no corporate proxy or another\n"
            "#   tenant's Client Connector), and PowerShell run as Administrator.\n"
            "# Run:  powershell -ExecutionPolicy Bypass -File .\\se-demo-zia-generator-setup.ps1\n"
            "#   or paste this whole file into an Administrator PowerShell window.\n"
            "# Then sign in to Client Connector as the test user. Progress: C:\\SE-Demo\\setup.log\n"
            "# It holds your app profile's policy token: keep it within your team, like the AWS template.\n")
    return head + body


def write_script(path, **kw):
    from pathlib import Path
    Path(path).write_text(setup_script(**kw), encoding="utf-8-sig", newline="\r\n")
    return path

