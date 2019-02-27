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
"""{{
    \"Parameters\" : {{
        \"AWS::IoT::Certificate::Country\" : {{
            \"Type\" : \"String\"
        }},
        \"AWS::IoT::Certificate::Id\" : {{
            \"Type\" : \"String\"
        }},
        \"AWS::IoT::Certificate::SerialNumber\" : {{
            \"Type\" : \"String\"
        }}
    }},
    \"Resources\" : {{
        \"thing\" : {{
            \"Type\" : \"AWS::IoT::Thing\",
            \"Properties\" : {{
                \"ThingName\" : {{
                    \"Ref\" : \"AWS::IoT::Certificate::SerialNumber\"
                }},
                \"AttributePayload\" : {{
                    \"serial\"  : {{
                        \"Ref\" : \"AWS::IoT::Certificate::SerialNumber\"
                    }},
                    \"version\" : \"v1\"
                }}
            }}
        }},
        \"certificate\" : {{
            \"Type\" : \"AWS::IoT::Certificate\",
            \"Properties\" : {{
                \"CertificateId\": {{
                    \"Ref\" : \"AWS::IoT::Certificate::Id\"
                }},
                \"Status\" : \"ACTIVE\"
            }}
        }},
        \"policy\" : {{
            \"Type\" : \"AWS::IoT::Policy\",
            \"Properties\" : {{
                \"PolicyName\": \"IoTAccess\"
                \"PolicyDocument\" : \"{{
                    \\\"Version\\\":\\\"2012-10-17\\\",
                    \\\"Statement\\\": [
                        {{
                            \\\"Sid\\\":\\\"MQTTConnect\\\",
                            \\\"Effect\\\":\\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Connect\\\"
                            ],
                            \\\"Resource\\\" : [
                                \\\"arn:aws:iot:{accountId}:{region}:client/${{iot:ClientId}}\\\"
                            ],
                            \\\"Condition\\\": {{
                                \\\"Bool\\\": {{
                                    \\\"iot:Connection.Thing.IsAttached\\\": [\\\"true\\\"]
                                }}
                            }}
                        }},
                        {{
                            \\\"Sid\\\":\\\"MQTTPublish\\\",
                            \\\"Effect\\\":\\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Publish\\\",
                                \\\"iot:GetThingShadow\\\",
                                \\\"iot:UpdateThingShadow\\\"
                            ],
                            \\\"Resource\\\" : [
                                \\\"arn:aws:iot:{accountId}:{region}:topic/foo/bar\\\",
                                \\\"arn:aws:iot:{accountId}:{region}:topic/$aws/things/${{iot:ClientId}}/shadow/get\\\",
                                \\\"arn:aws:iot:{accountId}:{region}:topic/$aws/things/${{iot:ClientId}}/shadow/update\\\",
                            ]
                        }},
                        {{
                            \\\"Sid\\\":\\\"MQTTSubscribe\\\",
                            \\\"Effect\\\":\\\"Allow\\\",
                            \\\"Action\\\": [
                                \\\"iot:Subscribe\\\",
                                \\\"iot:Receive\\\",
                                \\\"iot:GetThingShadow\\\"
                            ],
                            \\\"Resource\\\" : [
                                \\\"arn:aws:iot:{accountId}:{region}:topic/$aws/things/${{iot:ClientId}}/shadow/get/accepted\\\",
                                \\\"arn:aws:iot:{accountId}:{region}:topic/$aws/things/${{iot:ClientId}}/shadow/get/rejected\\\",
                                \\\"arn:aws:iot:{accountId}:{region}:topic/$aws/things/${{iot:ClientId}}/shadow/update/accepted\\\",
                                \\\"arn:aws:iot:{accountId}:{region}:topic/$aws/things/${{iot:ClientId}}/shadow/update/rejected\\\",
                                \\\"arn:aws:iot:{accountId}:{region}:topic/$aws/things/${{iot:ClientId}}/shadow/update/delta\\\"
                            ]
                        }}
                    ]
                }}\"
            }}
        }}
    }}
}}"""


IoTAccessCF_TEMPLATE_BODY = \
"""{
    \"AWSTemplateFormatVersion\" : \"2010-09-09\",
    \"Description\" : \"Setup IoTAccess policy\",
    \"Resources\" : {
        \"IoTAccess\" : {
            \"Type\" : \"AWS::IoT::Policy\",
            \"Properties" : {
                \"PolicyName\": \"IoTAccess\",
                \"PolicyDocument\" : {
                    \"Version\": \"2012-10-17\",
                    \"Statement\": [
                        {
                            \"Sid\":\"MQTTConnect\",
                            \"Effect\":\"Allow\",
                            \"Action\": [
                                \"iot:Connect\"
                            ],
                            \"Resource\" : [
                                {\"Fn::Join\":[ \"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":client/\",
                                    \"${iot:ClientId}\"
                                ]]}
                            ],
                            \"Condition\": {
                                \"Bool\": {
                                    \"iot:Connection.Thing.IsAttached\": [\"true\"]
                                }
                            }
                        },
                        {
                            \"Sid\":\"MQTTPublish\",
                            \"Effect\":\"Allow\",
                            \"Action\": [
                                \"iot:Publish\",
                                \"iot:GetThingShadow\",
                                \"iot:UpdateThingShadow\"
                            ],
                            \"Resource\" : [
                                {\"Fn::Join\":[\"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":topic/foo/bar\"
                                ]]},
                                {\"Fn::Join\":[\"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":topic/$aws/things/\",
                                    \"${iot:ClientId}\",
                                    \"/shadow/get\"
                                ]]},
                                {\"Fn::Join\":[\"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":topic/$aws/things/\",
                                    \"${iot:ClientId}\",
                                    \"/shadow/update\"
                                ]]}
                            ]
                        },
                        {
                            \"Sid\":\"MQTTSubscribe\",
                            \"Effect\":\"Allow\",
                            \"Action\": [
                                \"iot:Subscribe\",
                                \"iot:Receive\",
                                \"iot:GetThingShadow\"
                            ],
                            \"Resource\" : [
                                {\"Fn::Join\":[\"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":topic/$aws/things/\",
                                    \"${iot:ClientId}\",
                                    \"/shadow/get/accepted\"
                                ]]},
                                {\"Fn::Join\":[\"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":topic/$aws/things/\",
                                    \"${iot:ClientId}\",
                                    \"/shadow/get/rejected\"
                                ]]},
                                {\"Fn::Join\":[\"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":topic/$aws/things/\",
                                    \"${iot:ClientId}\",
                                    \"/shadow/update/delta\"
                                ]]},
                                {\"Fn::Join\":[\"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":topic/$aws/things/\",
                                    \"${iot:ClientId}\",
                                    \"/shadow/update/accepted\"
                                ]]},
                                {\"Fn::Join\":[\"\",[
                                    \"arn:aws:iot:\",
                                    {\"Fn::Sub\":\"${AWS::Region}\"},
                                    \":\",
                                    {\"Fn::Sub\":\"${AWS::AccountId}\"},
                                    \":topic/$aws/things/\",
                                    \"${iot:ClientId}\",
                                    \"/shadow/update/rejected\"
                                ]]}
                            ]
                        }
                    ]
                }
            }
        }
    }
}"""


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


def createCloudformationTemplate(template):
    ''' Create a Cloudformation Template.
    '''
    return str(template.replace('\n', '').replace(' ', ''))
