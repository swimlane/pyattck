from setuptools import setup, find_packages

def parse_requirements(requirement_file):
    with open(requirement_file) as f:
        return f.readlines()

version = dict()
with open("./pyattck/utils/version.py") as fp:
    exec(fp.read(), version)


setup(
    name='pyattck',
    version=version['__version__'],
    packages=find_packages(exclude=['tests*']),
    license='MIT',
    description='A Python package to interact with the Mitre ATT&CK Frameworks',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    install_requires=parse_requirements('./requirements.txt'),
    keywords=['att&ck', 'mitre', 'swimlane'],
    url='https://github.com/swimlane/pyattck',
    author='Swimlane',
    author_email='info@swimlane.com',
    python_requires='>=3.6, <4',
    package_data={},
    entry_points={
          'console_scripts': [
              'pyattck = pyattck.__main__:main'
          ]
    },
)
