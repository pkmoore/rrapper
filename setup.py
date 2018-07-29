from setuptools import setup, find_packages
from setuptools.extension import Extension

# Important constants
NAME = "rrapper"
VERSION = "0.1.0"
REPO = "https://github.com/pkmoore/rrapper"
DESC = """rrapper is a software suite under CrashSimulator that provides utilities for interacting with
a modified rr branch for record-replay debugging."""

CPUID_EXTENSION = Extension('cpuid', ['src/cpuid.c'],
                             extra_compile_args=["-Wall"])

# Main setup method
setup(
    name = NAME,
    version = VERSION,
    author = "Anonymous Authors",
    author_email = 'anonymous@authors.com',
    description = DESC,
    url=REPO,
    download_url='{}/archive/v{}'.format(REPO, VERSION),
    keywords=[
        'recordreplay',
        'debugging',
        'systems',
        'bugs',
    ],
    packages = find_packages(exclude=('tests',)),
    entry_points = {
        'console_scripts': [
            'rrinit=src.rrinit:main',
            'rreplay=src.rreplay:main'
        ],
    },
    install_requires=[
        'ConfigParser',
        'mock',
        'nose',
        'bunch',
        'tabulate',
    ],
    ext_modules=[
        CPUID_EXTENSION
    ]
)
