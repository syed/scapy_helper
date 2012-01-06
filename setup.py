from distutils.core import setup

setup(
    name='scapy_helper',
    version='0.1',
    author='Syed M Ahmed',
    author_email='syed1.mushtaq@gmail.com',
    packages=['scapy_helper'],
    url='http://url.com',
    license='LICENSE.txt',
    description='Simple TCP testing utitlity for scapy',
    long_description=open('README').read(),
    install_requires=[
        "scapy",
    ],
)
