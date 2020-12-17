import setuptools
setuptools.setup(
    name="JSINFO-SCAN",
    py_modules=['jsinfo'],
    entry_points={'console_scripts': ['jsinfo = jsinfo:_main']},
    install_requires=['aiohttp', 'loguru', 'tldextract'],
)
