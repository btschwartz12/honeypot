FROM debian:bullseye

# Install system dependencies.
RUN apt-get update && apt-get install -y \
    git \
    python3-virtualenv \
    libssl-dev \
    libffi-dev \
    build-essential \
    libpython3-dev \
    python3-minimal \
    authbind \
    virtualenv \
    python3-venv \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Add a user for Cowrie.
RUN adduser --disabled-password --gecos "" cowrie

RUN mkdir -p /home/cowrie/var/logs
RUN chown -R cowrie:cowrie /home/cowrie/var

# Switch to the cowrie user.
USER cowrie
WORKDIR /home/cowrie

# Clone the Cowrie repository.
RUN git clone http://github.com/cowrie/cowrie

# Set the working directory to the Cowrie directory.
WORKDIR /home/cowrie/cowrie

# Set up the virtual environment and install Python dependencies.
RUN python3 -m venv cowrie-env && \
    . cowrie-env/bin/activate && \
    python3 -m pip install --upgrade pip && \
    python3 -m pip install --upgrade -r requirements.txt

# Copy the necessary files from the host to the container.
COPY ./honeypot/cowrie.cfg ./etc/cowrie.cfg
COPY ./honeypot/userdb.txt ./etc/userdb.txt
COPY ./honeypot/fs.pickle ./share/cowrie/fs.pickle
COPY ./honeypot/txtcmds ./share/cowrie/txtcmds

CMD bash -c "if [ -z \"\$(ls -A /home/cowrie/cowrie/honeyfs)\" ]; then \
                echo 'real_honeyfs directory is empty, exiting with error'; \
                exit 1; \
              else \
                source cowrie-env/bin/activate && \
                bin/cowrie start && \
                tail -f /home/cowrie/var/logs/cowrie.log; \
              fi"
