from setuptools import setup
from os import path


setup(
    name='iot_device_provisioner',
    version='1.0.0',
    description='AWS IoT Device Provisioner',
    packages=['jitp', 'jitp.utilities'],
    install_requires=[
        'fire==0.1.3',
        'boto3==1.9.98',
        'botocore==1.12.98',
        'pyopenssl==19.0.0',
        'requests==2.21.0'
    ],
    entry_points={
        'console_scripts': ['jitp=jitp.jitpCommands:main'],
    },
    zip_safe=False
)
