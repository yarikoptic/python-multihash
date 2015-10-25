import sys
import setuptools
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        pass

    def run_tests(self):
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)

VERSION = '0.0.1'

setuptools.setup(
    name='multihash',
    description='An implementation of Multihash in Python',
    author='bmcorser',
    author_email='bmcorser@gmail.com',
    version=VERSION,
    packages=setuptools.find_packages(),
    tests_require=['pytest'],
    install_requires=['six'],
    cmdclass={'test': PyTest},
)
