from setuptools import setup, find_packages

with open('./README.md') as f:
    readme = f.read()

setup(
    name='aeif-lib',
    version='0.0.1',
    description='Encrypts and decrypts image files using AES encryption in GCM mode.',
    long_description=readme,
    long_description_content_type='text/markdown',
    author='Pekgame',
    author_email='pek795b@gmail.com',
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    python_requires='>=3.10',
    install_requires=['pycryptodome>=3.19.0'],
    license='MIT',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security :: Cryptography',
        'Operating System :: OS Independent'
    ],
    url='https://github.com/Pekgame/aeif-lib',
    extras_require={
        'dev': ['twine>=4.0.2']
    }
)
