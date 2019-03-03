# iot-device-provisioner


Linux (Ubuntu/Debian) Prerequisites:

```bash
$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```


Installation:

```bash
$ pip install git+https://github.com/petrichor-ai/iot-device-provisioner.git
```


Commands:

```bash
$ jitp create-service-role \
    --roleName (default 'IoT_JITP_Role')
```

```bash
$ jitp delete-service-role \
    --roleName (default 'IoT_JITP_Role')
```

```bash
$ jitp fetch-service-role \
    --roleName (default 'IoT_JITP_Role')
```

```bash
$ jitp generate-rootCA-cert \
    --certName (default 'rootCA')
    --C (Optional)
    --ST (Optional)
    --L (Optional)
    --O (Optional)
    --OU (Optional)
    --CN (default 'rootCA')
```

```bash
$ jitp generate-verify-cert \
    --certName (default 'verifyCert')
    --CA (default 'rootCA')
    --CAPath (default './')
    --C (Optional)
    --ST (Optional)
    --L (Optional)
    --O (Optional)
    --OU (Optional)
```

```bash
$ jitp generate-device-cert \
    --certName (default 'deviceCert')
    --thingName (default 'thing1')
    --productCode (default 1)
    --productNumber (default 1)
    --CA (default 'rootCA')
    --CAPath (default './')
    --C (Optional)
    --ST (Optional)
    --L (Optional)
    --O (Optional)
    --OU (Optional)
```

```bash
$ cat deviceCert.pem rootCA.pem > deviceCertAndCACert.pem
```


Tests:

```bash
$ python pub_client.py -e <AWS-IoT-Endpoint> -p 8883 -r root.cert -c deviceCertAndCACert.pem -k deviceCert.key -n <thingName> -id <clientId>
```

```bash
$ python sub_client.py -e <AWS-IoT-Endpoint> -p 8883 -r root.cert -c deviceCertAndCACert.pem -k deviceCert.key -n <thingName> -id <clientId>
```
