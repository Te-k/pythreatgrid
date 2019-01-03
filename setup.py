from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pythreatgrid2',
    version='0.1.1',
    description='Python wrapper around the Threat Grid API',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Te-k/pythreatgrid',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='security',
    install_requires=['requests'],
    license='MIT',
    python_requires='>=3.5',
    packages=['pythreatgrid2'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]

)
