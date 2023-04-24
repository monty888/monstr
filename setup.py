from setuptools import setup, find_packages

setup(name='monstr',
      version='0.1',
      packages=find_packages(),
      description='A module for working with monstr',
      url='https://github.com/monty888/monstr',
      author='Monty888',
      author_email='Monty888@protonmail.com',
      install_requires=[
            'aioconsole==0.6.0',
            'aiohttp==3.8.4',
            'aiosqlite==0.18.0',
            'bech32==1.2.0',
            'cachetools==5.3.0',
            'cryptography==39.0.1',
            'psycopg2==2.9.6',
            'secp256k1==0.14.0',
      ],
      license='MIT',
      zip_safe=False
)