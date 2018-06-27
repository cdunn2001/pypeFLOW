from setuptools import setup, Extension, find_packages
import subprocess

try:
    local_version = '+git.{}'.format(
        subprocess.check_output('git rev-parse HEAD', shell=True).strip().decode(encoding="utf-8"))
except Exception:
    local_version = ''

setup(
    name = 'pypeflow',
    version='2.0.3' + local_version,
    author='J. Chin',
    author_email='cschin@infoecho.net',
    license='LICENSE.txt',
    packages=find_packages(),
    package_dir = {'':'.'},
    zip_safe = False,
    install_requires=[
        'networkx >=1.7, <=1.11',
        'future >= 0.16.0',
    ],
    entry_points = {'console_scripts': [
            'pwatcher-main=pwatcher.mains.pwatcher:main',
            'pwatcher-pypeflow-example=pwatcher.mains.pypeflow_example:main',
            'heartbeat-wrapper=pwatcher.mains.fs_heartbeat:main',
            'snap=pypeflow.mains.snap:main',
        ],
    },
    package_data={'pwatcher.mains': ['*.sh']}
)
