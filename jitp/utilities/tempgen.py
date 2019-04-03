import json
import logging
import os


logging.basicConfig(
    format='%(asctime)s|%(name).10s|%(levelname).5s: %(message)s',
    level=logging.WARNING
)

log = logging.getLogger('tempgen')
log.setLevel(logging.DEBUG)



PROVISION_TEMPLATE_BODY = \
"""
{{
    \"Parameters\": {{
        \"AWS::IoT::Certificate::Id\": {{
            \"Type\": \"String\"
        }},
        \"AWS::IoT::Certificate::SerialNumber\": {{
            \"Type\": \"String\"
        }},
        \"AWS::IoT::Certificate::CommonName\": {{
            \"Type\": \"String\"
        }}
    }},
    \"Resources\": {{
        \"thing\": {{
            \"Type\": \"AWS::IoT::Thing\",
            \"Properties\": {{
                \"ThingName\": {{
                    \"Ref\": \"AWS::IoT::Certificate::CommonName\"
                }},
                \"AttributePayload\": {{
                    \"serial\": {{
                        \"Ref\": \"AWS::IoT::Certificate::SerialNumber\"
                    }}
                }}
            }}
        }},
        \"certificate\": {{
            \"Type\": \"AWS::IoT::Certificate\",
            \"Properties\": {{
                \"CertificateId\": {{
                    \"Ref\": \"AWS::IoT::Certificate::Id\"
                }},
                \"Status\": \"ACTIVE\"
            }}
        }},
        \"policy\": {{
            \"Type\": \"AWS::IoT::Policy\",
            \"Properties\": {{
                \"PolicyDocument\": \"{{
                    \\\"Version\\\":\\\"2012-10-17\\\",
                    \\\"Statement\\\": [
                        {{
                            \\\"Effect\\\": \\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Connect\\\"
                            ],
                            \\\"Resource\\\": [
                                \\\"arn:aws:iot:{region}:{accountId}:client/${{iot:ClientId}}\\\"
                            ],
                            \\\"Condition\\\": {{
                                \\\"Bool\\\": {{
                                    \\\"iot:Connection.Thing.IsAttached\\\": [\\\"true\\\"]
                                }}
                            }}
                        }},
                        {{
                            \\\"Effect\\\": \\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Publish\\\",
                                \\\"iot:GetThingShadow\\\",
                                \\\"iot:UpdateThingShadow\\\",
                                \\\"iot:DeleteThingShadow\\\"
                            ],
                            \\\"Resource\\\": [
                                \\\"arn:aws:iot:{region}:{accountId}:topic/$aws/things/${{iot:ClientId}}/shadow/+\\\"
                            ]
                        }},
                        {{
                            \\\"Effect\\\": \\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Subscribe\\\",
                                \\\"iot:Receive\\\"
                            ],
                            \\\"Resource\\\": [
                                \\\"arn:aws:iot:{region}:{accountId}:topicfilter/$aws/things/${{iot:ClientId}}/shadow/get/+\\\",
                                \\\"arn:aws:iot:{region}:{accountId}:topicfilter/$aws/things/${{iot:ClientId}}/shadow/update/+\\\",
                                \\\"arn:aws:iot:{region}:{accountId}:topicfilter/$aws/things/${{iot:ClientId}}/shadow/delete/+\\\",
                                \\\"arn:aws:iot:{region}:{accountId}:topic/$aws/things/${{iot:ClientId}}/shadow/get/+\\\",
                                \\\"arn:aws:iot:{region}:{accountId}:topic/$aws/things/${{iot:ClientId}}/shadow/update/+\\\",
                                \\\"arn:aws:iot:{region}:{accountId}:topic/$aws/things/${{iot:ClientId}}/shadow/delete/+\\\"
                            ]
                        }}
                    ]
                }}\"
            }}
        }}
    }}
}}
"""


def createProvisionTemplate(accountId, region, roleArn):
    ''' Create a Provisioning Template.
    '''

    template = PROVISION_TEMPLATE_BODY.format(
        accountId=accountId, region=region
    ).replace('\n', '').replace(' ', '')

    tempPayload = {}
    tempPayload["roleArn"] = roleArn
    tempPayload["templateBody"] = template
    return tempPayload
