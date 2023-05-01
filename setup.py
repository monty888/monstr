from setuptools import setup, find_packages

# read the contents of your README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(name='monstr',
      version='0.1.1',
      packages=find_packages(),
      description='Monstr: Python Nostr module. Python code for working with nostr.',
      long_description=long_description,
      long_description_content_type='text/markdown',
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