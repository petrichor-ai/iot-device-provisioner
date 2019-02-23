import boto3
import fire
import json
import logging
import os
import random
import sys

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto, SSL

from utilities.certgen import (createKeyPair, createCertRequest,
    createSelfSignedCertificate, createSignedCertificate,
    createCertFile, loadCertFile)
from utilities.tempgen import (createProvisionTemplate)
from utilities.uuidgen import (createEWonSerial)


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

        self._region         = s.region_name
        self._iam            = s.client('iam')
        self._iot            = s.client('iot')
        self._iot_endpoint   = self._iot.describe_endpoint()['endpointAddress']
        self._cloudformation = s.client('cloudformation')


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


    def generate_rootCA_cert(self, certName='rootCA'):
        ''' Generate a rootCA Certificate.
        '''

        pemFileOut = '{}.pem'.format(certName)
        keyFileOut = '{}.key'.format(certName)

        # Create rootCA KeyPair
        caKey  = createKeyPair(crypto.TYPE_RSA, 2048)

        # Create rootCA Certificate
        caPem = createSelfSignedCertificate(caKey, 50000000, (0, 60*60*24*365*5))

        # Create rootCA Pem/Key local files
        createCertFile(pemFileOut, caPem)
        createCertFile(keyFileOut, caKey)


    def generate_verify_cert(self, certName='verifyCert', CA='rootCA', CAPath='./'):

        pemFileOut = '{}.pem'.format(certName)
        keyFileOut = '{}.key'.format(certName)

        caPem = loadCertFile('{}.pem'.format(CA), CAPath)
        caKey = loadCertFile('{}.key'.format(CA), CAPath)


        # Retreive AWS IoT Cert Registration Code
        regCode = self._iot.get_registration_code()['registrationCode']

        # Create verifyCert KeyPair
        verifyKey  = createKeyPair(crypto.TYPE_RSA, 2048)

        # Create verifyCert Signing Request
        verifyReq = createCertRequest(verifyKey, C='US', ST='CA', L='LA', CN=regCode)

        # Create verifyCert Certificate
        verifyPem = createSignedCertificate(verifyReq, (caPem, caKey), 1, (0, 60*60*24*365*5))

        # Create verifyCert Pem/Key local files
        createCertFile(pemFileOut, verifyPem)
        createCertFile(keyFileOut, verifyKey)


        # Register verifyCert/rootCA with AWS IoT
        try:
            self._iot.register_ca_certificate(
                caCertificate=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, caPem
                )).decode('utf-8'),
                verificationCertificate=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, verifyPem
                )).decode('utf-8'),
                setAsActive=True
            )
        except ClientError as e:
            print(e)


    def generate_device_cert(self, certName='deviceCert', CA='rootCA', CAPath='./'):
        pass



def main():
    fire.Fire(jitpCommands())


if __name__ == '__main__':
    main()
