import boto3
import fire
import json
import logging
import os
import random
import sys

from botocore.exceptions import ClientError
from OpenSSL import crypto, SSL

from jitp.utilities import generateCertFiles


logging.basicConfig(
    format='%(asctime)s|%(name).10s|%(levelname).5s: %(message)s',
    level=logging.WARNING
)

log = logging.getLogger('jitpCommands')
log.setLevel(logging.DEBUG)



class jitpCommands(object):

    def __init__(self):
        super(jitpCommands, self).__init__()

        s = boto3.session.Session()
        if not s.region_name:
            raise Exception("AWS Credentials and Region must be setup")

        self._region       = s.region_name
        self._iam          = s.client('iam')
        self._iot          = s.client('iot')
        self._iot_endpoint = self._iot.describe_endpoint()['endpointAddress']


    def create_service_role(self, roleName='IoT_JITP_Role'):
        ''' Create IAM Service Role for JITP.

            :params  roleName: Name of the IAM Service Role
            :type    roleName: string
            :return: artifacts
            :rtype:  dict
        '''
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "iot.amazonaws.com"
                    ]
                },
                "Action": "sts:AssumeRole"
            }]
        }


        # Create AWS IAM Service Role (JITP)
        artifacts = {}
        try:
            response = self._iam.create_role(
                RoleName=roleName,
                Path='/service-role/',
                AssumeRolePolicyDocument=json.dumps(assume_role_policy)
            )

            artifacts['RoleName'] = response.get('Role', {}).get('RoleName', '')
            artifacts['Arn']      = response.get('Role', {}).get('Arn', '')

        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                log.info((
                    'AWS IAM Service Role {}, ' +
                    'already exists.'
                ).format(roleName))
            else:
                log.error((
                    'AWS IAM Service Role {}, ' +
                    'create encountered unexpected error.'
                ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'created successfully.'
            ).format(roleName))


        # Attach AWS IAM Service Role Policy (AWSIoTLogging)
        try:
            self._iam.attach_role_policy(
                RoleName=roleName,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSIoTLogging'
            )
        except ClientError as e:
            log.error((
                'AWS IAM Service Role {}, ' +
                'attach AWSIoTLogging Policy failed.'
            ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'attach AWSIoTLogging Policy successful.'
            ).format(roleName))


        # Attach AWS IAM Service Role Policy (AWSIoTRuleActions)
        try:
            self._iam.attach_role_policy(
                RoleName=roleName,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSIoTRuleActions'
            )
        except ClientError as e:
            log.error((
                'AWS IAM Service Role {}, ' +
                'attach AWSIoTRuleActions Policy failed.'
            ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'attach AWSIoTRuleActions Policy successful.'
            ).format(roleName))


        # Attach AWS IAM Service Role Policy (AWSIoTThingsRegistration)
        try:
            self._iam.attach_role_policy(
                RoleName=roleName,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration'
            )
        except ClientError as e:
            log.error((
                'AWS IAM Service Role {}, ' +
                'attach AWSIoTThingsRegistration Policy failed.'
            ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'attach AWSIoTThingsRegistration Policy successful.'
            ).format(roleName))

        return artifacts if artifacts else None


    def delete_service_role(self, roleName='IoT_JITP_Role'):
        ''' Delete IAM Service Role for JITP.

            :params  roleName: Name of the IAM Service Role
            :type    roleName: string
        '''

        # Detach AWS IAM Service Role Policy (AWSIoTLogging)
        try:
            self._iam.detach_role_policy(
                RoleName=roleName,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSIoTLogging'
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                log.info((
                    'AWS IAM Service Role {}, ' +
                    'does not exist.'
                ).format(roleName))
            else:
                log.error((
                    'AWS IAM Service Role {}, ' +
                    'detach AWSIoTLogging Policy encountered unexpected error.'
                ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'detach AWSIoTLogging Policy successful.'
            ).format(roleName))


        # Detach AWS IAM Service Role Policy (AWSIoTRuleActions)
        try:
            self._iam.detach_role_policy(
                RoleName=roleName,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSIoTRuleActions'
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                log.info((
                    'AWS IAM Service Role {}, ' +
                    'does not exist.'
                ).format(roleName))
            else:
                log.error((
                    'AWS IAM Service Role {}, ' +
                    'detach AWSIoTRuleActions Policy encountered unexpected error.'
                ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'detach AWSIoTRuleActions Policy successful.'
            ).format(roleName))


        # Detach AWS IAM Service Role Policy (AWSIoTThingsRegistration)
        try:
            self._iam.detach_role_policy(
                RoleName=roleName,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration'
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                log.info((
                    'AWS IAM Service Role {}, ' +
                    'does not exist.'
                ).format(roleName))
            else:
                log.error((
                    'AWS IAM Service Role {}, ' +
                    'detach AWSIoTThingsRegistration Policy encountered unexpected error.'
                ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'detach AWSIoTThingsRegistration Policy successful.'
            ).format(roleName))


        # Delete AWS IAM Service Role (JITP)
        try:
            self._iam.delete_role(
                RoleName=roleName
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                log.info((
                    'AWS IAM Service Role {}, ' +
                    'does not exist.'
                ).format(roleName))
            else:
                log.error((
                    'AWS IAM Service Role {}, ' +
                    'delete encountered unexpected error.'
                ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'delete successful.').format(roleName))


    def fetch_service_role(self, roleName='IoT_JITP_Role'):
        ''' Retreive IAM Service Role for JITP.

            :params  roleName: Name of the IAM Service Role
            :type    roleName: string
            :return: artifacts
            :rtype:  dict
        '''

        # Fetch AWS IAM Service Role (JITP)
        artifacts = {}
        try:
            response = self._iam.get_role(
                RoleName=roleName
            )
            artifacts['RoleName'] = response.get('Role', {}).get('RoleName', '')
            artifacts['Arn']      = response.get('Role', {}).get('Arn', '')

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                log.info((
                    'AWS IAM Service Role {}, ' +
                    'does not exist.'
                ).format(roleName))
            else:
                log.error((
                    'AWS IAM Service Role {}, ' +
                    'fetch encountered unexpected error.'
                ).format(roleName), exc_info=True)
            return
        else:
            log.info((
                'AWS IAM Service Role {}, ' +
                'fetch successful.').format(roleName))

        return artifacts if artifacts else None


def main():
    fire.Fire(jitpCommands())


if __name__ == '__main__':
    main()
