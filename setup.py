#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='cors',
    version='1.0.1',
    description='Fast CORS misconfiguration vulnerabilities scanner',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Jianjun Chen',
    author_email= 'whucjj@hotmail.com',
    url='http://github.com/chenjj/CORScanner',
    project_urls={  
        'Bug Reports': 'https://github.com/chenjj/CORScanner/issues',
        'Source': 'https://github.com/chenjj/CORScanner/',
    },
    license='MIT',
    packages=find_packages(),
    install_requires=['colorama', 'requests', 'argparse', 'gevent', 'tldextract', 'future', 'PySocks'],
    include_package_data=True,
    zip_safe=False,
    # https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Environment :: Console',
        'Topic :: Security',
    ],
    entry_points={
        'console_scripts': [
            'cors = CORScanner.cors_scan:main',
        ],
    },
)
