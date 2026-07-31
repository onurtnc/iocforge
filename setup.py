from setuptools import find_packages, setup

setup(
    name="iocforge",
    version="1.0.0",
    description="IOC cikarma, tehdit istihbarati zenginlestirme ve skorlama araci",
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.8",
    entry_points={"console_scripts": ["iocforge=iocforge.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
