# this is to create security layer by creating security groups 
import boto3
from config.config import *
from core.utils import logger

ec2 = boto3.client("ec2", region_name=REGION)


def get_default_vpc():
    response = ec2.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["true"]}]
    )
    return response["Vpcs"][0]["VpcId"]


def get_security_group_by_name(name):
    try:
        response = ec2.describe_security_groups(GroupNames=[name])
        return response["SecurityGroups"][0]["GroupId"]
    except Exception:
        return None


def create_alb_security_group():
    vpc_id = get_default_vpc()

    sg_id = get_security_group_by_name(ALB_SG_NAME)
    if sg_id:
        logger.info(f"ALB SG already exists: {sg_id}")
        return sg_id

    response = ec2.create_security_group(
        GroupName=ALB_SG_NAME,
        Description="ALB Security Group",
        VpcId=vpc_id
    )

    sg_id = response["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )

    logger.info(f"Created ALB SG: {sg_id}")
    return sg_id


def create_ec2_security_group(my_ip, alb_sg_id):
    vpc_id = get_default_vpc()

    sg_id = get_security_group_by_name(EC2_SG_NAME)
    if sg_id:
        logger.info(f"EC2 SG already exists: {sg_id}")
        return sg_id

    response = ec2.create_security_group(
        GroupName=EC2_SG_NAME,
        Description="EC2 Security Group",
        VpcId=vpc_id
    )

    sg_id = response["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            # SSH from your IP
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": f"{my_ip}/32"}]
            },
            # HTTP only from ALB
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "UserIdGroupPairs": [{"GroupId": alb_sg_id}]
            }
        ]
    )

    logger.info(f"Created EC2 SG: {sg_id}")
    return sg_id