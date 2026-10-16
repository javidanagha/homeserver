FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    USER=linkspace \
    DISPLAY=:1

RUN apt-get update && apt-get install -y --no-install-recommends \
        xfce4 xfce4-terminal xfce4-goodies \
        tigervnc-standalone-server tigervnc-common tigervnc-tools \
        dbus-x11 sudo ca-certificates curl nano git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ${USER} \
    && echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER}

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

USER ${USER}
WORKDIR /home/${USER}
EXPOSE 5901
CMD ["/usr/local/bin/start.sh"]
