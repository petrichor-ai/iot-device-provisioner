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
        }
    },
    \"Resources\" : {
        \"thing\" : {
            \"Type\" : \"AWS::IoT::Thing\",
            \"Properties\" : {
                \"ThingName\" : {
                    \"Ref\" : \"AWS::IoT::Certificate::Id\"
                },
                \"AttributePayload\" : {
                    \"version\" : \"v1\",
                    \"country\" : {
                        \"Ref\" : \"AWS::IoT::Certificate::Country\"
                    }
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
                    \\\"Statement\\\": [{
                        \\\"Effect\\\":\\\"Allow\\\",
                        \\\"Action\\\": [
                            \\\"iot:Connect\\\",
                            \\\"iot:Publish\\\"
                        ],
                        \\\"Resource\\\" : [
                            \\\"*\\\"
                        ]
                    }]
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
