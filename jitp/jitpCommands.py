import boto3
import fire
import json
import logging
import os
import random
import requests
import sys

from botocore.exceptions import ClientError
from OpenSSL import crypto, SSL

from utilities.certgen import (createECDSAKey, createKeyPair,
    createCertRequest, createSelfSignedCertificate,
    createSignedCertificate, createCertFile, loadCertFile)
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
        self._sts            = s.client('sts')
        self._accountId      = self._sts.get_caller_identity().get('Account')
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


    def generate_rootCA_cert(self, certName='rootCA',
        C='', ST='', L='', O='', OU='', CN='rootCA'):
        ''' Generate a rootCA Certificate.
        '''
        crtFileOut = '{}.crt'.format(certName)
        keyFileOut = '{}.key'.format(certName)

        # Create rootCA KeyPair
        caKey = createKeyPair(crypto.TYPE_RSA, 2048)

        # Create rootCA Certificate
        serialNumber = random.randint(1000000, 9000000)
        caCrt = createSelfSignedCertificate(
            caKey, serialNumber, (0, 60*60*24*365*5),
            C=C, ST=ST, L=L, O=O, OU=OU, CN=CN
        )

        # Create rootCA Crt/Key local files
        createCertFile(crtFileOut, caCrt, crypto.FILETYPE_PEM)
        createCertFile(keyFileOut, caKey, crypto.FILETYPE_PEM)

        return caKey, caCrt


    def generate_verify_cert(self, certName='verifyCert',
        CA='rootCA', CAPath='./', C='', ST='', L='', O='', OU=''):
        ''' Generate a Verification Certificate.
        '''
        crtFileOut = '{}.crt'.format(certName)
        keyFileOut = '{}.key'.format(certName)

        caCrt = loadCertFile('{}.crt'.format(CA), CAPath)
        caKey = loadCertFile('{}.key'.format(CA), CAPath)


        # Retreive AWS IoT Cert Registration Code
        regCode = self._iot.get_registration_code()['registrationCode']

        # Create verifyCert KeyPair
        verifyKey  = createKeyPair(crypto.TYPE_RSA, 2048)

        # Create verifyCert Signing Request
        verifyReq = createCertRequest(verifyKey, C=C, ST=ST, L=L, O=O, OU=OU, CN=regCode)

        # Create verifyCert Certificate
        serialNumber = random.randint(1000000, 9000000)
        verifyCrt = createSignedCertificate(verifyReq, (caCrt, caKey), serialNumber, (0, 60*60*24*365*5))

        # Create verifyCert Crt/Key local files
        createCertFile(crtFileOut, verifyCrt, crypto.FILETYPE_PEM)
        createCertFile(keyFileOut, verifyKey, crypto.FILETYPE_PEM)

        # Register verifyCert/rootCA with AWS IoT
        try:
            roleArn = self.fetch_service_role()['Arn']
            self._iot.register_ca_certificate(
                caCertificate=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, caCrt
                )).decode('utf-8'),
                verificationCertificate=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, verifyCrt
                )).decode('utf-8'),
                setAsActive=True,
                allowAutoRegistration=True,
                registrationConfig=createProvisionTemplate(
                    self._accountId, self._region, roleArn
                )
            )

            log.info((
                'AWS IoT CA Certificate: {}, ' +
                'registered successfully'
            ).format(CA))

            self._iot.register_certificate(
                certificatePem=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, verifyCrt
                )).decode('utf-8'),
                caCertificatePem=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, caCrt
                )).decode('utf-8'),
                setAsActive=True
            )

            log.info((
                'AWS IoT Verify Certificate: {}, ' +
                'registered successfully'
            ).format(certName))
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                log.error(e.response['Error']['Message'])
                log.info('Regenerate rootCA and retry...', exc_info=True)
            else:
                log.error((
                    'AWS IoT CA and Verify Certificate: {} {}, ' +
                    'registration encountered unexpected error'
                ).format(CA, certName), exc_info=True)

        return verifyKey, verifyReq, verifyCrt


    def generate_device_cert(self, thingName, productCode=1, productNumber=1,
            certType='RSA', CA='rootCA', CAPath='./',
            C='', ST='', L='', O='', OU=''):
        ''' Generate a Device Certificate.
        '''
        crtFileOut = '{}.crt'.format(thingName)
        keyFileOut = '{}.key'.format(thingName)

        caCrt = loadCertFile('{}.crt'.format(CA), CAPath)
        caKey = loadCertFile('{}.key'.format(CA), CAPath)


        # Create deviceCert KeyPair
        if certType == 'RSA':
            deviceKey = createKeyPair(crypto.TYPE_RSA, 2048)
        elif certType == 'EC':
            deviceKey = createECDSAKey('SECP256R1')
        else:
            return 'certificate type not supported. must be of type `RSA` or `EC`'

        # Create deviceCert Signing Request
        deviceReq = createCertRequest(deviceKey, C=C, ST=ST, L=L, O=O, OU=OU, CN=thingName)

        # Create deviceCert Certificate
        serialNumber = createEWonSerial(productCode, productNumber)
        deviceCrt = createSignedCertificate(deviceReq, (caCrt, caKey), serialNumber, (0, 60*60*24*365*5))

        # Create deviceCert Crt/Key local files
        createCertFile(crtFileOut, deviceCrt, crypto.FILETYPE_PEM)
        createCertFile(keyFileOut, deviceKey, crypto.FILETYPE_PEM)

        return deviceKey, deviceReq, deviceCrt


    def fetch_iot_root_cert(self, certName='root'):
        ''' Download AWS IoT Symantec root CA.
        '''
        crtFileOut = '{}.cert'.format(certName)

        # Fetch Symantec rootCA
        resp = requests.get((
            'https://www.symantec.com' +
            '/content/en/us/enterprise/verisign/roots' +
            '/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem'
        ))

        # Load Symantec rootCA
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, resp.text)

        # Create Symantec rootCA local file
        createCertFile(crtFileOut, cert, crypto.FILETYPE_PEM)



def main():
    fire.Fire(jitpCommands())



if __name__ == '__main__':
    main()
