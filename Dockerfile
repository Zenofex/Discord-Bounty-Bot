# Use an official Python runtime as a parent image
FROM ubuntu:latest

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for Python and tools
RUN apt-get update && apt-get install -y \
    git \
    nmap \
    curl \
    software-properties-common \
    build-essential \
    ruby-full \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Ruby Bundler
RUN gem install bundler

# Install Arachni
RUN git clone https://github.com/Arachni/arachni.git /usr/local/src/arachni && \
    cd /usr/local/src/arachni && \
    bundle install

#install chromedriver
RUN CHROMEDRIVER_VERSION=`curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE` && \
    mkdir -p /opt/chromedriver-$CHROMEDRIVER_VERSION && \
    curl -sS -o /tmp/chromedriver_linux64.zip http://chromedriver.storage.googleapis.com/$CHROMEDRIVER_VERSION/chromedriver_linux64.zip && \
    unzip -qq /tmp/chromedriver_linux64.zip -d /opt/chromedriver-$CHROMEDRIVER_VERSION && \
    rm /tmp/chromedriver_linux64.zip && \
    chmod +x /opt/chromedriver-$CHROMEDRIVER_VERSION/chromedriver && \
    ln -fs /opt/chromedriver-$CHROMEDRIVER_VERSION/chromedriver /usr/local/bin/chromedriver

# Install dnsrecon
RUN git clone https://github.com/darkoperator/dnsrecon.git /usr/local/src/dnsrecon

WORKDIR  /usr/local/src/dnsrecon

RUN pip3 install -r requirements.txt

# Install sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /usr/local/src/sqlmap

WORKDIR  /usr/local/src/sqlmap

RUN curl "https://raw.githubusercontent.com/theMiddleBlue/DNSenum/master/wordlist/subdomains-top1mil-5000.txt" -o /usr/local/src/subdomain-dictionary.txt

# Switch back to /app workdir
WORKDIR /app

# Install dirb
RUN apt-get update && apt-get install -y dirb && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
COPY src .

COPY requirements.txt .

# Install Python dependencies
RUN pip3 install -r /app/requirements.txt

# Set environment variables for tool locations
ENV ARACHNI_LOC="/usr/local/src/arachni/bin/arachni" \
    ARACHNI_REPORTER_LOC="/usr/local/src/arachni/bin/arachni_reporter" \
    DNSRECON_LOC="/usr/local/src/dnsrecon/dnsrecon.py" \
    SQLMAP_LOC="/usr/local/src/sqlmap/sqlmap.py" \
    DIRB_LOC="dirb" \
    NMAP_LOC="nmap"

# Run the Discord bot when the container launches
CMD ["python3", "bug_bounty_bot.py"]
