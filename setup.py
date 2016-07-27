#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Setup file for ZMON AWS agent
"""

import sys
import os

from setuptools.command.test import test as TestCommand
from setuptools import setup, find_packages


def read_version(package):
    data = {}
    with open(os.path.join(package, '__init__.py'), 'r') as fd:
        exec(fd.read(), data)
    return data['__version__']


def get_requirements(path):
    content = open(path).read()
    return [req for req in content.split('\\n') if req != '']


MAIN_PACKAGE = 'zmon_aws_agent'
VERSION = read_version(MAIN_PACKAGE)
DESCRIPTION = 'ZMon AWS agent.'

CONSOLE_SCRIPTS = ['zmon-aws-agent = zmon_aws_agent.main:main']


class PyTest(TestCommand):

    user_options = [
        ('cov=', None, 'Run coverage'),
        ('cov-xml=', None, 'Generate junit xml report'),
        ('cov-html=', None, 'Generate junit html report'),
    ]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.cov = None
        self.cov_xml = False
        self.cov_html = False

    def finalize_options(self):
        TestCommand.finalize_options(self)
        if self.cov is not None:
            self.cov = ['--cov', self.cov, '--cov-report', 'term-missing']
            if self.cov_html:
                self.cov.extend(['--cov-report', 'html'])
            if self.cov_xml:
                self.cov.extend(['--cov-report', 'xml'])

    def run_tests(self):
        try:
            import pytest
        except:
            raise RuntimeError('py.test is not installed, run: pip install pytest')

        params = {'args': self.test_args}
        if self.cov:
            params['args'] += self.cov

        errno = pytest.main(**params)
        sys.exit(errno)


setup(
    name='zmon-aws-agent',
    version=VERSION,
    description=DESCRIPTION,
    long_description=open('README.rst').read(),
    license=open('LICENSE').read(),
    packages=find_packages(exclude=['tests']),
    install_requires=get_requirements('requirements.txt'),
    test_suite='tests',
    cmdclass={
        'test': PyTest
    },
    entry_points={
        'console_scripts': CONSOLE_SCRIPTS
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation :: CPython',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking :: Monitoring'
    ]
)
