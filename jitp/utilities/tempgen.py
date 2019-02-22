import json


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
    template["templateBody"] = TEMPLATE_BODY
    return template
