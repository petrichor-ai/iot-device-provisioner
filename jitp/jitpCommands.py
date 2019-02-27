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

from utilities.certgen import (createKeyPair, createCertRequest,
    createSelfSignedCertificate, createSignedCertificate,
    createCertFile, loadCertFile)
from utilities.tempgen import (createProvisionTemplate, createCloudformationTemplate,
   PROVISION_TEMPLATE_BODY, IoTAccessCF_TEMPLATE_BODY
)
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


    def create_IoTAccess_policy(self, policyName='IoTAccess'):
        ''' Create a IoTAccess IoT policy
        '''
        stackName    = '{}-Policy-Stack'.format(policyName)
        templateBody = createCloudformationTemplate(IoTAccessCF_TEMPLATE_BODY)
        try:
            self._cloudformation.create_stack(
                StackName=stackName,
                TemplateBody=templateBody,
                OnFailure='DELETE',
                EnableTerminationProtection=False
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'AlreadyExistsException':
                log.error((
                    'AWS Cloudformation Stack: {}, ' +
                    'already exists.'
                ).format(stackName))
            else:
                log.error((
                    'AWS Cloudformation Stack: {}, ' +
                    'create encountered unexcepted error.'
                ).format(stackName), exc_info=True)
            return
        else:
            log.info((
                'AWS Cloudformation Stack: {}, ' +
                'created successfully.'
            ).format(stackName))


    def delete_IoTAccess_policy(self, policyName='IoTAccess'):
        ''' Delete an IoTAccess IoT policy
        '''
        stackName    = '{}-Policy-Stack'.format(policyName)
        try:
            self._cloudformation.delete_stack(
                StackName=stackName
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                log.error((
                    'AWS Cloudformation Stack: {}, ' +
                    'does not exist.'
                ).format(stackName))
            else:
                log.error((
                    'AWS Cloudformation Stack: {}, ' +
                    'delete encountered unexcepted error.'
                ).format(stackName), exc_info=True)
            return
        else:
            log.info((
                'AWS Cloudformation Stack: {}, ' +
                'deleted successfully.'
            ).format(stackName))



    def generate_rootCA_cert(self, certName='rootCA'):
        ''' Generate a rootCA Certificate.
        '''

        pemFileOut = '{}.pem'.format(certName)
        keyFileOut = '{}.key'.format(certName)

        # Create rootCA KeyPair
        caKey  = createKeyPair(crypto.TYPE_RSA, 2048)

        # Create rootCA Certificate
        serialNumber = random.randint(1000000, 9000000)
        caPem = createSelfSignedCertificate(caKey, serialNumber, (0, 60*60*24*365*5))

        # Create rootCA Pem/Key local files
        createCertFile(pemFileOut, caPem)
        createCertFile(keyFileOut, caKey)


    def generate_verify_cert(self, certName='verifyCert', CA='rootCA', CAPath='./'):
        ''' Generate a Verification Certificate.
        '''
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
        serialNumber = random.randint(1000000, 9000000)
        verifyPem = createSignedCertificate(verifyReq, (caPem, caKey), serialNumber, (0, 60*60*24*365*5))

        # Create verifyCert Pem/Key local files
        createCertFile(pemFileOut, verifyPem)
        createCertFile(keyFileOut, verifyKey)


        # Register verifyCert/rootCA with AWS IoT
        try:
            roleArn = self.fetch_service_role()['Arn']
            self._iot.register_ca_certificate(
                caCertificate=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, caPem
                )).decode('utf-8'),
                verificationCertificate=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, verifyPem
                )).decode('utf-8'),
                setAsActive=True,
                allowAutoRegistration=True,
                registrationConfig=createProvisionTemplate(roleArn, PROVISION_TEMPLATE_BODY)
            )

            self._iot.register_certificate(
                certificatePem=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, verifyPem
                )).decode('utf-8'),
                caCertificatePem=str(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, caPem
                )).decode('utf-8'),
                setAsActive=True
            )
        except ClientError as e:
            print(e)
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                log.error(e.response['Error']['Message'])
                log.info('Regenerate rootCA and retry...')


    def generate_device_cert(self, certName='deviceCert', productCode=1,
            productNumber=1, CA='rootCA', CAPath='./'):
        ''' Generate a Device Certificate.
        '''
        pemFileOut = '{}.pem'.format(certName)
        keyFileOut = '{}.key'.format(certName)

        caPem = loadCertFile('{}.pem'.format(CA), CAPath)
        caKey = loadCertFile('{}.key'.format(CA), CAPath)


        # Retreive AWS IoT Cert Registration Code
        regCode = self._iot.get_registration_code()['registrationCode']

        # Create deviceCert KeyPair
        deviceKey  = createKeyPair(crypto.TYPE_RSA, 2048)

        # Create deviceCert Signing Request
        deviceReq = createCertRequest(deviceKey, C='US', ST='CA', L='LA', CN=regCode)

        # Create deviceCert Certificate
        serialNumber = createEWonSerial(productCode, productNumber)
        devicePem = createSignedCertificate(deviceReq, (caPem, caKey), serialNumber, (0, 60*60*24*365*5))

        # Create deviceCert Pem/Key local files
        createCertFile(pemFileOut, devicePem)
        createCertFile(keyFileOut, deviceKey)


    def fetch_iot_root_cert(self, certName='root'):

        pemFileOut = '{}.cert'.format(certName)

        # Fetch Symantec rootCA
        resp = requests.get('https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem')

        # Create Symantec rootCA local file
        createCertFile(pemFileOut, resp.text)


def main():
    fire.Fire(jitpCommands())



if __name__ == '__main__':
    main()
