from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

recommended = {
    "cffi": ["cffi>1.11.5"]
}

install_requires = [
    "cffi>=1.11.5"
]

setup(name='pySafe',
      version='0.1',
      description='Python interface to the SAFE binaries',
      long_description=readme(),
      classifiers=[
            'Development Status :: 1 - Dev',
            'License :: OSI Approved :: GPL3 License',
            'Programming Language :: Python :: 3.6+',
            'Topic :: File Utilities and Management',
      ],
      url='',
      license='GPL3',
      packages=['pySafe'],
      zip_safe=False)