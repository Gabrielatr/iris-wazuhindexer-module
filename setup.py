from setuptools import setup

setup(
    name='iris-wazuhindexer-module',
    python_requires='>=3.10',
    version='0.1.1',
    packages=['iris_wazuhindexer_module', 'iris_wazuhindexer_module.wazuhindexer_handler'],
    url='https://github.com/iris_wazuhindexer_module/iris-wazuhindexer-module',
    license='MIT',
    author='Gabrielatr',
    author_email='hello@iris-wazuhindexer-module.com',
    description='`iris-wazuhindexer-module` is a IRIS pipeline/processor module created with https://github.com/dfir-iris/iris-skeleton-module',
    install_requires=['opensearch-py==3.0.0']
)
