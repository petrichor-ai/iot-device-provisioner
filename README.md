## AWS IoT-Device-Provisioner (JITP)


### Linux (Ubuntu/Debian) Prerequisites:

```bash
$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```


### Installation:

```bash
$ pip install git+https://github.com/petrichor-ai/iot-device-provisioner.git
```


### Commands:

Create a IAM Service Role,
```bash
$ jitp create-service-role \
    --roleName               (default 'IoT_JITP_Role')
```

Delete a IAM Service Role,
```bash
$ jitp delete-service-role \
    --roleName               (default 'IoT_JITP_Role')
```

Fetch a IAM Service Role,
```bash
$ jitp fetch-service-role \
    --roleName               (default 'IoT_JITP_Role')
```

Generate a rootCA Certificate,
```bash
$ jitp generate-rootCA-cert \
    --certName               (default 'rootCA')
    --C                      (Optional)
    --ST                     (Optional)
    --L                      (Optional)
    --O                      (Optional)
    --OU                     (Optional)
    --CN                     (default 'rootCA')
```

Generate a Verify Certificate,
```bash
$ jitp generate-verify-cert \
    --certName               (default 'verifyCert')
    --CA                     (default 'rootCA')
    --CAPath                 (default './')
    --C                      (Optional)
    --ST                     (Optional)
    --L                      (Optional)
    --O                      (Optional)
    --OU                     (Optional)
```

Generate a Device Certificate,
```bash
$ jitp generate-device-cert \
    --thingName              (required)
    --productCode            (default 1)
    --productNumber          (default 1)
    --certType               (default 'RSA' or 'EC')
    --CA                     (default 'rootCA')
    --CAPath                 (default './')
    --C                      (Optional)
    --ST                     (Optional)
    --L                      (Optional)
    --O                      (Optional)
    --OU                     (Optional)
```

Chain Device and rootCA Certificates,
```bash
$ cat deviceCert.pem rootCA.pem > deviceCertAndCACert.pem
```


### Examples:

Python Pub Cli
```bash
$ python pub_client.py -e <AWS-IoT-Endpoint> -p 8883 -r root.cert -c deviceCertAndCACert.pem -k deviceCert.key -n <thingName> -id <clientId>
```

Python Sub Cli
```bash
$ python sub_client.py -e <AWS-IoT-Endpoint> -p 8883 -r root.cert -c deviceCertAndCACert.pem -k deviceCert.key -n <thingName> -id <clientId>
```

Mosquitto Pub CLI
```bash
$ mosquitto_pub --cert thing-0.pem --key thing-0.prv --cafile aws-iot-rootCA.crt -h
XXXXXXXXYYYYY.iot.us-west-2.amazonaws.com -p 8883 -t 'test/thing' -m "Hello from Mosquitto"
```

Mosquitto Sub CLI
```bash
$ mosquitto_sub --cert thing-0.pem --key thing-0.prv --cafile aws-iot-rootCA.crt -h
XXXXXXXXYYYYY.iot.us-west-2.amazonaws.com -p 8883 -t 'test/+'
```
