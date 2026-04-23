import boto3
import requests
import os

from botocore.exceptions import ClientError
from config.config import *
from core.utils import logger

ec2 = boto3.client("ec2", region_name=REGION)


# -----------------------------
# Get latest Amazon Linux 2 AMI
# -----------------------------
def get_latest_ami():
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )

    latest = sorted(images["Images"], key=lambda x: x["CreationDate"], reverse=True)[0]
    return latest["ImageId"]


# -----------------------------
# Create / Reuse Key Pair
# -----------------------------
def create_key_pair():
    os.makedirs("keys", exist_ok=True)
    key_path = f"keys/{KEY_NAME}.pem"

    try:
        response = ec2.create_key_pair(KeyName=KEY_NAME)

        with open(key_path, "w") as f:
            f.write(response["KeyMaterial"])

        os.chmod(key_path, 0o400)

        logger.info(f"Key pair created: {KEY_NAME}")

    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidKeyPair.Duplicate":
            logger.info(f"Key already exists: {KEY_NAME}")

            # Ensure local key exists (important for SSH)
            if not os.path.exists(key_path):
                logger.warning("Key exists in AWS but not locally. Recreate manually if needed.")
        else:
            raise


# -----------------------------
# Read local website
# -----------------------------
def load_website():
    with open("app/index.html", "r") as f:
        return f.read()


# -----------------------------
# Build user data script
# -----------------------------
def build_user_data(html_content):
    return f"""#!/bin/bash
yum update -y
yum install -y httpd

systemctl start httpd
systemctl enable httpd

cat <<EOF > /var/www/html/index.html
{html_content}
EOF

systemctl restart httpd
"""


# -----------------------------
# Launch EC2 instance
# -----------------------------
def launch_instance(security_group_id):
    ami = get_latest_ami()
    html = load_website()
    user_data = build_user_data(html)

    response = ec2.run_instances(
        ImageId=ami,
        InstanceType=INSTANCE_TYPE,
        MinCount=1,
        MaxCount=1,
        KeyName=KEY_NAME,
        SecurityGroupIds=[security_group_id],
        UserData=user_data,

        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': PROJECT_TAG_KEY, 'Value': PROJECT_TAG_VALUE}
                ]
            }
        ]
    )

    instance_id = response["Instances"][0]["InstanceId"]

    logger.info(f"Instance launched: {instance_id}")

    # Wait until running
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])

    logger.info("Instance is running")

    return instance_id


# -----------------------------
# Get public IP (optional)
# -----------------------------
def get_my_ip():
    return requests.get("https://api.ipify.org").text