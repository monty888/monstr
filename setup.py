import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(name='monstr',
                 version='0.1',
                 description='A module for working with monstr',
                 long_description=long_description,
                 long_description_content_type="text/markdown",
                 url='https://github.com/monty888/monstr',
                 author='Monty888',
                 author_email='Monty888@protonmail.com',
                 license='MIT',
                 zip_safe=False,
                 package_dir={"": "monstr"},
                 packages=setuptools.find_packages(where="monstr"))
