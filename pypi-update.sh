#! /bin/bash

# check inputs
if [ $# -eq 2 ]
  then
    echo "Usage: pypi-update.sh ${PYPI_USER} ${PYPI_PASSWORD}"
fi

# build and upload
poetry publish --build -u $1 -p $2
