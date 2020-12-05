from setuptools import setup

setup(
    name='etrx3x_sim',
    version='0.0.1',
    description='Simulator to test Services built on top of ETR3x ZigBee'
                'Network',
    url='https://github.com/rumassa86/etrx3x-network-simulator',
    author='Rubens Massayuki Suguimoto',
    author_email='rubens.suguimoto@gmail.com',
    license='SG',
    packages=[
        "etrx3x_sim"
    ],
    install_requires=[
    ],
    package_dir={
        'etrx3x_sim': 'lib'
    },
    platforms='any',
    include_package_data=True,
    zip_safe=False
)
