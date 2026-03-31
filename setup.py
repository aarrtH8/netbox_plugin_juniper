from setuptools import setup, find_packages

setup(
    name='netbox-plugin-juniper',
    version='1.2.0',
    description='Plugin NetBox pour scanner et intégrer les firewalls Juniper',
    author='Arthur',
    license='MIT',
    install_requires=[
        'paramiko>=2.12.0',
    ],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)