FROM golang:1.7

# Install zip
RUN apt-get -y update && \
    apt-get -y install zip

ENV GOPATH=/

# Download and install tools
RUN echo "Installing the godep tool"
RUN go get github.com/tools/godep

ADD . /src/github.com/IBM-Bluemix/bluemix-cli-openwhisk

# Load all of the dependencies from the previously generated/saved godep generated godeps.json file
RUN echo "Restoring Go dependencies"
RUN cd /src/github.com/IBM-Bluemix/bluemix-cli-openwhisk && /bin/godep restore -v

# wsk binary will be placed under a build folder
RUN mkdir /src/github.com/IBM-Bluemix/bluemix-cli-openwhisk/build

ARG CLI_OS
ARG CLI_ARCH

# Build the Go wsk CLI binaries and compress resultant binaries
RUN chmod +x /src/github.com/IBM-Bluemix/bluemix-cli-openwhisk/build.sh
RUN cd /src/github.com/IBM-Bluemix/bluemix-cli-openwhisk && ./build.sh
