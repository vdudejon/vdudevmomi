from setuptools import find_packages, setup

setup(
    name="vdudevmomi",
    version="0.0.2",
    url="https://github.com/vdudejon/vdudevmomi",
    author="vdudejon",
    packages=find_packages(exclude=["tests", "tests.*", "examples"]),
    install_requires=[
        "pyvim>=3.0.3",
        "pyvmomi>=8.0.2.0",
        "requests",
    ],
)
