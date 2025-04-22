from setuptools import setup, find_packages
import os

# Чтение README.md для long_description
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='mirajeweb',
    version='1.0.0',
    author='TheTemirBolatov',
    author_email='your_email@example.com',  # Замените на ваш реальный email
    description='The most secure and lightweight web framework for building protected websites',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/ftoop17/mirajeweb',
    project_urls={
        'Bug Tracker': 'https://github.com/ftoop17/mirajeweb/issues',
        'Documentation': 'https://github.com/ftoop17/mirajeweb/wiki',
    },
    license='Proprietary',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Operating System :: OS Independent',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Security',
    ],
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    python_requires='>=3.7',
    install_requires=[],  # Нет зависимостей - все включено
    extras_require={
        'dev': [
            'pytest>=6.2.4',
            'coverage>=5.5',
        ],
    },
    keywords=[
        'web',
        'framework',
        'security',
        'django',
        'flask',
        'alternative',
        'lightweight',
        'secure',
    ],
    entry_points={
        'console_scripts': [
            'mirajeweb=mirajeweb.cli:main',  # Если будет CLI
        ],
    },
    include_package_data=True,
    zip_safe=False,
    options={
        'bdist_wheel': {
            'universal': True  # Чистый Python пакет
        }
    },
)