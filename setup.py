from setuptools import setup

setup(
    name='etrx3x_sim',
    version='0.0.0',
    description='ETRX3x simulator to test performance of SG Gateway (Concentrador)',
    url='http://repositorio.smartgreen.net.br/network/etrx3x-network-simulator',
    author='Rubens Massayuki Suguimoto',
    author_email='rubens@smartgreen.com',
    license='SG',
    packages=[
        "etrx3x_sim"
    ],
    install_requires=[
        "sgcon>=1.0.0"
    ],
    package_dir={
        'etrx3x_sim': 'lib'
    },
    platforms='any',
    include_package_data=True,
    zip_safe=False
)
