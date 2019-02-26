import json
import logging
import os


logging.basicConfig(
    format='%(asctime)s|%(name).10s|%(levelname).5s: %(message)s',
    level=logging.WARNING
)

log = logging.getLogger('tempgen')
log.setLevel(logging.DEBUG)



TEMPLATE_BODY = \
"""{
    \"Parameters\" : {
        \"AWS::IoT::Certificate::Country\" : {
            \"Type\" : \"String\"
        },
        \"AWS::IoT::Certificate::Id\" : {
            \"Type\" : \"String\"
        },
        \"AWS::IoT::Certificate::SerialNumber\" : {
            \"Type\" : \"String\"
        }
    },
    \"Resources\" : {
        \"thing\" : {
            \"Type\" : \"AWS::IoT::Thing\",
            \"Properties\" : {
                \"ThingName\" : {
                    \"Ref\" : \"AWS::IoT::Certificate::SerialNumber\"
                },
                \"AttributePayload\" : {
                    \"serial\"  : {
                        \"Ref\" : \"AWS::IoT::Certificate::SerialNumber\"
                    },
                    \"version\" : \"v1\"
                }
            }
        },
        \"certificate\" : {
            \"Type\" : \"AWS::IoT::Certificate\",
            \"Properties\" : {
                \"CertificateId\": {
                    \"Ref\" : \"AWS::IoT::Certificate::Id\"
                },
                \"Status\" : \"ACTIVE\"
            }
        },
        \"policy\" : {
            \"Type\" : \"AWS::IoT::Policy\",
            \"Properties\" : {
                \"PolicyDocument\" : \"{
                    \\\"Version\\\": \\\"2012-10-17\\\",
                    \\\"Statement\\\": [
                        {
                            \\\"Effect\\\":\\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Connect\\\"
                            ],
                            \\\"Resource\\\" : [
                                \\\"*\\\"
                            ]
                        },
                        {
                            \\\"Effect\\\":\\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Publish\\\"
                            ],
                            \\\"Resource\\\" : [
                                \\\"arn:aws:iot:::topic/foo/bar\\\",
                                \\\"arn:aws:iot:::topic/$aws/things/${iot:Connection.Thing.ThingName}/shadow/get\\\",
                                \\\"arn:aws:iot:::topic/$aws/things/${iot:Connection.Thing.ThingName}/shadow/update\\\"
                            ]
                        },
                        {
                            \\\"Effect\\\":\\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Subscribe\\\"
                            ],
                            \\\"Resource\\\" : [
                                \\\"arn:aws:iot:::topic/$aws/things/${iot:ClientId}/shadow/get/accepted\\\",
                                \\\"arn:aws:iot:::topic/$aws/things/${iot:ClientId}/shadow/get/rejected\\\",
                                \\\"arn:aws:iot:::topic/$aws/things/${iot:ClientId}/shadow/update/delta\\\",
                                \\\"arn:aws:iot:::topic/$aws/things/${iot:ClientId}/shadow/update/accepted\\\",
                                \\\"arn:aws:iot:::topic/$aws/things/${iot:ClientId}/shadow/update/rejected\\\"
                            ]
                        }
                    ]
                }\"
            }
        }
    }
}"""


def createProvisionTemplate(roleArn):
    ''' Create a Provisioning Template
    '''
    template = {}
    template["roleArn"] = roleArn
    template["templateBody"] = TEMPLATE_BODY.replace('\n', '').replace(' ', '')
    return template
