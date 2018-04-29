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
      keywords='safenetwork safenet interface',
      url='https://github.com/rid-dim/pySafe/tree/dev',
      license='GPL3',
      packages=['pySafe'],
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'safeAuth=pySafe:Authenticator', # I just thought it would be cool to have a simple and basic authenticator available in the command line
              'safeConn=pySafe:ConnTest',      # and maybe a connection test as well - rid
          ],}
      )
