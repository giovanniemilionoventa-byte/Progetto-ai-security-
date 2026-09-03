from setuptools import find_packages, setup

setup(
    name="aegis-sdk",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["httpx>=0.27"],
)
