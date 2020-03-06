FROM registry.labs.nic.cz/knot/knot-resolver/ci/debian-buster:knot-2.9
WORKDIR /
RUN git clone --recurse-submodules -j8 --depth=1 https://gitlab.labs.nic.cz/knot/knot-resolver.git kresd-local-build
WORKDIR kresd-local-build
RUN meson build_local --default-library=static -Dsendmmsg=disabled
RUN ninja -C build_local install
WORKDIR /
RUN git clone https://gitlab.labs.nic.cz/knot/deckard.git
WORKDIR /deckard
RUN make depend
ENV TMPDIR /deckard