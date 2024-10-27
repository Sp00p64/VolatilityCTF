FROM accenturecifr/volatility3

RUN apk add git curl

RUN git clone https://github.com/spitfirerxf/vol3-plugins.git && \
    git clone https://github.com/kudelskisecurity/volatility-gpg.git && \
    git clone https://github.com/fox-it/OpenSSH-Session-Key-Recovery.git 

RUN python3 -m pip install cryptography stream_sqlite striprtf python-evtx
#RUN cd OpenSSH-Session-Key-Recovery && cd pip-package && python3 setup.py install
RUN cp vol3-plugins/* /usr/lib/python3.10/site-packages/volatility3-2.7.0-py3.10.egg/volatility3/framework/plugins/windows

COPY discord.py /usr/lib/python3.10/site-packages/volatility3-2.7.0-py3.10.egg/volatility3/framework/plugins/windows
COPY zbotscan.py /usr/lib/python3.10/site-packages/volatility3-2.7.0-py3.10.egg/volatility3/framework/plugins/windows

RUN cp volatility-gpg/linux/* /usr/lib/python3.10/site-packages/volatility3-2.7.0-py3.10.egg/volatility3/framework/plugins/linux
#RUN curl https://raw.githubusercontent.com/fox-it/OpenSSH-Session-Key-Recovery/main/volatility3/openssh_sessionkeys.py --output /usr/lib/python3.10/site-packages/volatility3-2.5.1-py3.10.egg/volatility3/framework/plugins/linux/openssh_sessionkeys.py
