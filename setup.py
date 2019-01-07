from setuptools import setup, find_packages

setup(
    name='pyattck',
    version='0.1.0',
    packages=find_packages(exclude=['tests*']),
    license='MIT',
    description='A package to interact with the Mitre ATT&CK Framework',
    long_description=open('README.MD').read(),
    install_requires=[],
    url='',
    author='Josh Rickard',
    author_email='josh.rickard@swimlane.com'
)