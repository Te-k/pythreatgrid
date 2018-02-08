from setuptools import setup

setup(
    name='pythreatgrid',
    version='0.1.1',
    description='Python wrapper around the Threat Grid API',
    url='https://github.com/Te-k/pythreatgrid',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='security',
    install_requires=['requests'],
    license='MIT',
    python_requires='>=3.5',
    packages=['pythreatgrid'],
    #entry_points= {
        #'console_scripts': [ 'threatgrid=pythreatgrid.cli:main' ]
    #}
)
