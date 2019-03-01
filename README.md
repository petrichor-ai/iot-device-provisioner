# iot-device-provisioner


Linux (Ubuntu/Debian) Prerequisites:

```bash
$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```


Installation:

```bash
$ pip install git+https://github.com/petrichor-ai/iot-device-provisioner.git
```


Steps:

```bash
$ jitp generate-rootCA-cert
```

```bash
$ jitp generate-verify-cert
```

```bash
$ jitp generate-device-cert
```

```bash
$ cat deviceCert.pem rootCA.pem > deviceCertAndCACert.pem
```


Tests:

```bash
$ python pub_client.py -e <AWS-IoT-Endpoint> -p 8882 -r root.cert -c deviceCertAndCACert.pem -k deviceCert.key -n <thingName> -id <clientId>
```

```bash
$ python pub_client.py -e <AWS-IoT-Endpoint> -p 8882 -r root.cert -c deviceCertAndCACert.pem -k deviceCert.key -n <thingName> -id <clientId>
```
