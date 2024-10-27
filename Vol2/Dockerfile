FROM ubuntu:bionic as base

RUN apt-get update \
  && apt-get install -y git python python-distorm3 python-crypto \
  && git clone https://github.com/volatilityfoundation/volatility.git \
  && rm -rf /volatility/.git \
  && apt-get -y remove --purge git \
  && apt-get -y autoremove \
  && apt-get -y clean \
  && rm -rf /var/lib/apt/lists/*
  
VOLUME /dumps

WORKDIR /volatility

FROM base

USER root

ENV TZ=Asia/Dubai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt update && apt install -y curl

RUN apt-get install -y build-essential autoconf libtool pkg-config idle-python2.7 python-dev openssl libssl-dev git

RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py

RUN python2 get-pip.py

RUN pip install yara-python==4.2.3 

RUN ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so

RUN git clone https://github.com/monnappa22/Psinfo.git 

RUN cp Psinfo/psinfo.py volatility/plugins

RUN git clone https://github.com/coderforlife/ms-compress

RUN cd ms-compress && ./build.sh && mv libMSCompression.so /usr/lib

RUN pip install pillow

RUN git clone https://github.com/superponible/volatility-plugins.git /tmp/test

RUN cp /tmp/test/* volatility/plugins/

RUN curl https://raw.githubusercontent.com/superponible/volatility-plugins/master/prefetch.py --output volatility/plugins/prefetch.py && \
    curl https://raw.githubusercontent.com/Memoryforensics/carve_packets/master/carve_packets.py --output volatility/plugins/carve_packets.py && \
    curl https://raw.githubusercontent.com/tomchop/volatility-autoruns/master/autoruns.py --output volatility/plugins/autoruns.py && \
    curl https://raw.githubusercontent.com/volatilityfoundation/community/master/BartoszInglot/schtasks.py --output volatility/plugins/shtasks.py && \ 
    curl https://raw.githubusercontent.com/fox-it/OpenSSH-Session-Key-Recovery/main/volatility2/openssh_sessionkeys.py --output volatility/plugins/openssh_sessionkeys.py && \
    curl -L https://github.com/volatilityfoundation/profiles/raw/master/Mac/10.8/x64/MountainLion_10.8.1_AMD.zip --output volatility/plugins/overlays/mac/MountainLion_10.8.1_AMD.zip && \
    curl -L https://raw.githubusercontent.com/tribalchicken/volatility-filevault2/master/plugins/mac/filevault2.py --output volatility/plugins/filevault2.py && \
    curl -L https://raw.githubusercontent.com/breppo/Volatility-BitLocker/master/bitlocker.py --output volatility/plugins/bitlocker.py

COPY discord.py volatility/plugins/
COPY zeusscan1.py volatility/plugins/
COPY zeusdecode.py volatility/plugins/
RUN mkdir -p /home/vol/profiles

COPY ./profiles/ /home/vol/profiles

ENTRYPOINT ["python", "vol.py"]