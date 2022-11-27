FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libpcap-dev libssl-dev clang

COPY . /repo
WORKDIR /repo
ENV DESTDIR=/install
RUN CC=clang CXX=clang++ make -j8
RUN CC=clang CXX=clang++ make install
RUN ar rcs libthc-ipv6.a thc-ipv6-lib.o
RUN clang++ /repo/mayhem/fuzz_thc_resolve6.cpp -fsanitize=fuzzer,address -L /repo/ -lthc-ipv6 -flto -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_thc_resolve6
