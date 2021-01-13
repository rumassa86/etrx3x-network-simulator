from setuptools import setup
from distutils.util import convert_path

# Get version from version file
etrx3x_sim_ns = {}
ver_path = convert_path('etrx3x_sim/version.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), etrx3x_sim_ns)

setup(
    name='etrx3x_sim',
    version=etrx3x_sim_ns['__version__'],
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
        'etrx3x_sim': 'etrx3x_sim'
    },
    entry_points={
        'console_scripts': [
            'etrx3x_sim=etrx3x_sim.etrx3x_sim:main',
        ]
    },
    platforms='any',
    include_package_data=True,
    zip_safe=False
)
