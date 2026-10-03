from setuptools import setup, find_packages

setup(
    name="datashield-sdk",
    version="1.0.0",
    author="masbin",
    author_email="masbin-dev@users.noreply.github.com",
    description="Python Client & Fraud Intelligence SDK for DataShield APIs",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/jarumgoni/masbin-dev",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
)
