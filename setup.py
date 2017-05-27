"""
Flask-Cavage
-------------

Flask Cavage provides verification and authentication of requests that
been signed using cavage-http-signature.

Please see

 - https://tools.ietf.org/html/draft-cavage-http-signatures-06

This library has been tested using requests signed by

 - https://github.com/tomitribe/http-signatures-java
 - https://pypi.python.org/pypi/httpsig_cffi/15.0.0
"""
from setuptools import setup


setup(
    name='Flask-Cavage',
    version='0.4.2',
    url='https://github.com/labeneator/flask_cavage',
    license='GPLv3',
    author='Laban Mwangi',
    author_email='lmwangi@gmail.com',
    description='Verify cavage-http-signatures requests made to Flask',
    long_description=__doc__,
    py_modules=['flask_cavage'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask', 'httpsig'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
