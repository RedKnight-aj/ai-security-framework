from setuptools import setup, find_packages

setup(
    name="ai-security-framework",
    version="1.0.0",
    description="Production-ready AI Security Framework using Promptfoo",
    author="RedKnight AI",
    author_email="redknight@ai.com",
    url="https://github.com/RedKnight-aj/ai-security-framework",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        "promptfoo>=0.50.0",
        "pytest>=7.0.0",
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
    ],
)
