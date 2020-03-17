#! /bin/bash

# check inputs
if [ $# -eq 2 ]
  then
    echo "Usage: pypi-update.sh ${PYPI_USER} ${PYPI_PASSWORD}"
fi

# build
python setup.py sdist bdist_wheel

# upload
twine upload --skip-existing -u $1 -p $2 --repository-url https://upload.pypi.org/legacy/ dist/*
