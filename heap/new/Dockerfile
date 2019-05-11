FROM ubuntu:16.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.aliyun.com/g" /etc/apt/sources.list
RUN apt-get update && apt-get -y dist-upgrade
RUN apt-get install -y lib32z1 xinetd build-essential ssh

RUN mkdir /root/.ssh/ && chmod -R 700 /root/.ssh/
RUN sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbf3BmsMcE8H0zWImI8wGzrRc9uX4ZpX8Arxt+Z5t/b3S4DUXHfcvpnogVgOyux7NQDiKKYKbeu/234UQiysqoYNRMFnyy3vq4Biu7RlBizSCbJ3nDBrspmwNmkt4eY3ze8dyPJo7kt8fn8bBpo/W3KAkhJ8xcuKs1sfnOaOcU0x5HvFQN+3xAQkaXCcQme31SaW3A5F5/4tz3DQZPw/pxa0kCCLseATn01+GZ15iYDq04BxzqtI7RAQz2qWc5NscYDGrbunm+Hxrus/NsC0b+ZY051K9vpCGgsIDFkKTCFxuLO9RpqxpEkaoksQ6bPddV2IolZ8mqtWN/wtvoRdHL" >> /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys


RUN groupadd ciscn && \
    useradd -g ciscn ciscn -m && \
    password=$(openssl passwd -1 -salt 'abcdefg' '123456') && \
    sed -i 's/^ciscn:!/ciscn:'$password'/g' /etc/shadow

RUN useradd -m ctf

COPY ./flag /flag
COPY ./pwn /pwn/pwn
COPY ./ctf.xinetd /etc/xinetd.d/ctf

RUN chown root:ctf /pwn/pwn && chmod 750 /pwn/pwn

RUN echo 'ctf - nproc 1500' >>/etc/security/limits.conf

CMD exec /bin/bash -c "/etc/init.d/xinetd start; trap : TERM INT; sleep infinity & wait"

EXPOSE 8888 
