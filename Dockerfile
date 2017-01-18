FROM ubuntu:latest
MAINTAINER David Kilgore <dkilgore@ucsc.edu>

# Establish the main folder/directory.
ENV DCC_HOME /dcc
RUN mkdir -p ${DCC_HOME}
WORKDIR ${DCC_HOME}

# Install system and pip packages.
RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install python python-virtualenv docker python-pip
COPY ./dashboard.py .
COPY ./requirements.txt .
RUN virtualenv env
RUN /bin/bash -c 'source env/bin/activate'
RUN pip install --upgrade pip
RUN pip install -r ./requirements.txt

# Extra steps before running the server.
RUN mkdir static
COPY ./static static/
RUN mkdir templates
COPY ./templates templates/
EXPOSE 8000

# Start the server.
CMD python dashboard.py ${CLIENT_ID} ${CLIENT_SECRET} 8000
