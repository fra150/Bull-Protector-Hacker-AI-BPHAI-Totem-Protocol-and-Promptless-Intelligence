"""Setup configuration for BPHAI package."""

from setuptools import setup, find_packages
import os

# Read the README file for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements from requirements.txt
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#") and not line.startswith("python")]

setup(
    name="bphai",
    version="1.0.0",
    author="BPHAI Development Team",
    author_email="dev@bphai.org",
    description="Behavioral Pattern Hashing AI - Advanced prompt injection resistance system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bphai/bphai",
    project_urls={
        "Bug Tracker": "https://github.com/bphai/bphai/issues",
        "Documentation": "https://bphai.readthedocs.io/",
        "Source Code": "https://github.com/bphai/bphai",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.11.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
        "web": [
            "fastapi>=0.100.0",
            "uvicorn>=0.23.0",
            "streamlit>=1.25.0",
        ],
        "ml": [
            "scikit-learn>=1.3.0",
            "transformers>=4.30.0",
            "torch>=2.0.0",
        ],
        "database": [
            "sqlalchemy>=2.0.0",
            "aiosqlite>=0.19.0",
        ],
        "cache": [
            "redis>=4.6.0",
            "aioredis>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "bphai=bphai.cli:main",
            "bphai-test=bphai.testing:run_tests",
            "bphai-demo=bphai.demo:run_demo",
        ],
    },
    include_package_data=True,
    package_data={
        "bphai": [
            "config/*.yaml",
            "config/*.json",
            "data/*.txt",
            "templates/*.html",
        ],
    },
    zip_safe=False,
    keywords=[
        "ai",
        "security",
        "prompt-injection",
        "neural-networks",
        "nlp",
        "machine-learning",
        "cybersecurity",
        "artificial-intelligence",
    ],
)