from setuptools import setup, find_packages

setup(
    name="jsdeob",
    version="1.1",
    description="JSDeob - JavaScript Deobfuscation Tool for Malware Analysis",
    author="Connell",
    author_email="connell543@outlook.com",
    url="https://github.com/connell543/jsdeob",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.10.0",
        "prompt_toolkit>=3.0.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "malware": ["yara-python>=4.2.0"],
    },
    entry_points={
        "console_scripts": [
            "jsdeob=jsdeob.cli:main"
        ]
    },
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
