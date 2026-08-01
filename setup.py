from setuptools import setup, find_packages

setup(
    name="vulnvista",
    version="2.0.0",
    description="Professional Open-Source Web Vulnerability Scanner",
    author="cyberseef",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "markdown2",
        "pdfkit",
        "rich"
    ],
    entry_points={
        "console_scripts": [
            "vulnvista=vuln_vista:main"
        ]
    },
    python_requires=">=3.7",
)
