FROM ghcr.io/astral-sh/uv:0.12.6 AS uv

FROM kalilinux/kali-rolling

COPY --from=uv /uv /uvx /usr/local/bin/

ARG CAI_VERSION=0.5.5
ARG CAI_UPSTREAM_COMMIT=6d47ccc2d282d6ec42243aa524019adb6bf48127
ARG CAI_PATCH_SHA256=BCD203CA619DAECB4DDBCC1E3FFDE3D2383ED4ECE90A57DE1590CD91B2C78568

# Set environment variable to non-interactive
ENV DEBIAN_FRONTEND=noninteractive

# Fix Kali Linux repository GPG key issues
RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --no-install-recommends --allow-unauthenticated kali-archive-keyring && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# [Optional] Uncomment this section to install additional OS packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    net-tools python3 python3-pip python3-venv \
    curl gnupg nmap iputils-ping ssh git \
    graphviz pkg-config libhdf5-dev \
    build-essential python3-dev \
    asciinema dnsutils \
    apt-transport-https ca-certificates \
    wget dirb gobuster whatweb gfortran \
    cmake libopenblas-dev sshpass seclists \
    golang-go

# # Install Metasploit - path 1
# RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall \
#     && chmod 755 /tmp/msfinstall \
#     && /tmp/msfinstall

# # Install Metasploit - path 2
# RUN curl https://apt.metasploit.com/metasploit-framework.gpg.key | apt-key add -
# RUN echo "deb https://apt.metasploit.com/ lucid main" | tee /etc/apt/sources.list.d/metasploit-framework.list
# RUN apt-get update && apt-get install metasploit-framework

# Install Metasploit - path 3
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall

# Update Kali Linux repositories
RUN apt-get update \
    && apt-get upgrade -y

# Install rust compiler - dependency of outlines-core
RUN apt-get update && \
    apt-get install -y curl && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . $HOME/.cargo/env && \
    rustup default stable && \
    rustup component add rustfmt clippy && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"
RUN wget https://raw.githubusercontent.com/adfoster-r7/metasploit-info/master/info/module_metadata.json -O /tmp/module_metadata.json

# Update and upgrade packages
# Preconfigure console-setup and install kali-linux-headless fixers
RUN apt-get update && \
    echo "console-setup console-setup/variant select Latin1 and Latin5 - western Europe and Turkic languages" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends kali-linux-headless

# Install docker inside of dev env
RUN apt-get update && \
    apt-get install -y apt-transport-https ca-certificates curl gnupg && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian bullseye stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce docker-ce-cli containerd.io cloc

RUN cargo install --git https://github.com/asciinema/agg


# Install MulVAL
# Dependency setup
RUN sudo apt install -y build-essential default-jdk flex bison graphviz texlive-font-utils xutils-dev git
# Get XSB and configure installation
RUN wget "https://sourceforge.net/projects/xsb/files/xsb/5.0%20%28Green%20Tea%29/XSB-5.0.tar.gz/download" -O - | \
    sudo tar -zx -C /usr/local/bin
RUN sudo mv /usr/local/bin/XSB /usr/local/bin/xsb-5.0.0 && \
    cd /usr/local/bin/xsb-5.0.0/build && \
    sudo ./configure --prefix=/usr/local/bin && \
    sudo ./makexsb && \
    sudo ./makexsb install

# Clone and patch the MulVAL repo to be ran on newer Linux versions 
RUN cd ~ && git clone https://github.com/risksense/mulval.git && \
    cd mulval && \
    wget "https://patch-diff.githubusercontent.com/raw/risksense/mulval/pull/9.patch" -O - | git apply - && \
    export MULVALROOT=$(pwd) && \
    make

# Set environment variables permanently for MulVAL and XSB
ENV MULVALROOT=/root/mulval
ENV DOTNET_ROOT=/root/.dotnet
ENV PATH="${PATH}:${MULVALROOT}/bin:${MULVALROOT}/utils:/usr/local/bin/xsb-5.0.0/bin:${DOTNET_ROOT}:${DOTNET_ROOT}/tools"

# Install .NET 9 SDK and AppInspector
RUN apt-get update && apt-get install -y libicu-dev && \
    cd ~ && \
    wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh && \
    chmod +x dotnet-install.sh && \
    ./dotnet-install.sh --channel 9.0 && \
    rm dotnet-install.sh && \
    /root/.dotnet/dotnet tool install -g Microsoft.CST.ApplicationInspector.CLI

# Install the exact Trivy version verified by the Hydra release smoke test.
RUN apt-get update && \
    apt-get install -y --no-install-recommends trivy=0.66.0-0kali1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Keep CAI and Semgrep isolated from Kali's system Python packages. CAI supports Python 3.12;
# Semgrep has a separate environment so its dependencies cannot alter the CAI environment.
ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python
ENV CAI_VIRTUAL_ENV=/opt/cai-venv
ENV SEMGREP_VIRTUAL_ENV=/opt/semgrep-venv
RUN uv python install 3.12.14 && \
    uv venv --seed --python 3.12.14 "${CAI_VIRTUAL_ENV}" && \
    uv venv --python 3.12.14 "${SEMGREP_VIRTUAL_ENV}" && \
    uv pip install --python "${SEMGREP_VIRTUAL_ENV}/bin/python" semgrep==1.168.0

COPY patches/cai-0.5.5-hydra.patch /tmp/cai-0.5.5-hydra.patch
RUN echo "${CAI_PATCH_SHA256}  /tmp/cai-0.5.5-hydra.patch" | sha256sum -c - && \
    git init /opt/cai-source && \
    git -C /opt/cai-source remote add origin https://github.com/aliasrobotics/cai.git && \
    git -C /opt/cai-source fetch --depth 1 origin "${CAI_UPSTREAM_COMMIT}" && \
    git -C /opt/cai-source checkout --detach FETCH_HEAD && \
    test "$(git -C /opt/cai-source rev-parse HEAD)" = "${CAI_UPSTREAM_COMMIT}" && \
    git -C /opt/cai-source apply --check /tmp/cai-0.5.5-hydra.patch && \
    git -C /opt/cai-source apply /tmp/cai-0.5.5-hydra.patch

RUN uv pip install --python "${CAI_VIRTUAL_ENV}/bin/python" \
        --editable /opt/cai-source "tiktoken>=0.7,<1"
RUN uv pip check --python "${CAI_VIRTUAL_ENV}/bin/python"
RUN "${CAI_VIRTUAL_ENV}/bin/python" -c \
        "import importlib.metadata as m; import cai; assert m.version('cai-framework') == '${CAI_VERSION}'; assert m.version('openai') == '1.75.0'"
RUN env OPENAI_API_KEY=sk-1234 \
        CAI_TRACING=false \
        OPENAI_AGENTS_DISABLE_TRACING=true \
        "${CAI_VIRTUAL_ENV}/bin/cai" --help >/dev/null
RUN test "$("${SEMGREP_VIRTUAL_ENV}/bin/semgrep" --version)" = "1.168.0"
RUN test "$(dpkg-query -W -f='${Version}' trivy)" = "0.66.0-0kali1"

ENV VIRTUAL_ENV=${CAI_VIRTUAL_ENV}
ENV PATH="${CAI_VIRTUAL_ENV}/bin:${SEMGREP_VIRTUAL_ENV}/bin:${PATH}"

# Configure passwordless sudo for nmap (required for OS detection -O flag)
# This allows the scanner to run nmap with OS detection without password prompts
RUN echo 'ALL ALL=(root) NOPASSWD: /usr/bin/nmap' > /etc/sudoers.d/nmap && \
    chmod 0440 /etc/sudoers.d/nmap
