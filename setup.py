from setuptools import setup
from os import path


setup(
    name='iot_device_provisioner',
    version='1.0.0',
    description='AWS IoT Device Provisioner',
    packages=['jitp'],
    install_requires=[
        'fire',
        'boto3',
        'botocore',
        'pyopenssl'
    ],
    entry_points={
        'console_scripts': ['jitp=jitp.jitpCommands:main'],
    },
    zip_safe=False
)
