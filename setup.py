from setuptools import setup, find_packages

def parse_requirements(requirement_file):
    with open(requirement_file) as f:
        return f.readlines()

setup(
    name='pyattck',
    version='1.0.0',
    packages=find_packages(exclude=['tests*']),
    license='MIT',
    description='A Python package to interact with the Mitre ATT&CK Framework',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    install_requires=parse_requirements('./requirements.txt'),
    keywords='att&ck mitre swimlane',
    url='https://github.com/swimlane/pyattck',
    author='Swimlane',
    author_email='info@swimlane.com'
)