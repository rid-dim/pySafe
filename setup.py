from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

recommended = {
    "cffi": ["cffi>1.11.5"]
}

setup(name='safenet-dev',
      version='0.2',
      description='Python interface to the SAFE binaries',
      long_description=readme(),
      classifiers=[
            'Development Status :: 2 - Pre-Alpha',
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 3.6',
      ],
      keywords='safenetwork safenet interface',
      url='https://github.com/rid-dim/pySafe/tree/dev',
      license='GPL3',
      packages=['safenet'],
      include_package_data=True,
      install_requires=[
          'cffi',
          'multihash',
          'py-cid',
          'requests',
          'werkzeug',
          'pyOpenSSL',
      ],
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'safeAuth=safenet:Authenticator', # I just thought it would be cool to have a simple and basic authenticator available in the command line
              'safeConn=safenet:ConnTest',      # and maybe a connection test as well - rid
          ],}
      )
