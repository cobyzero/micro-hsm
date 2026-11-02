# ==============================================================================
# Utimaco SecurityServer / PaymentServer Official Simulator v6.6.0.0
# Basado en los binarios oficiales incluidos en ext/u.trust-GP-HSM-Simulator_v6.6.0.0:
#   - Simulador: bl_sim5 (ELF 32-bit i386) + devices (FLASHFILE, NVRAMFILE, MK, SDRAM)
#   - Administración: csadm, p11tool2, cxitool (ELF 64-bit x86_64) + ADMIN.key
#   - Driver PKCS#11: libcs_pkcs11_R3.so (ELF 64-bit x86_64)
# ==============================================================================
FROM --platform=linux/amd64 ubuntu:22.04

LABEL version="6.6.0.0"
LABEL maintainer="Security Architecture Team"
LABEL description="Official Utimaco HSM Simulator v6.6.0.0 (bl_sim5 + PKCS#11 R3)"

ARG SimulatorPort=3015
ENV DEBIAN_FRONTEND=noninteractive

# Habilitar arquitectura i386 (necesaria para el binario bl_sim5 de 32-bits de Utimaco)
# e instalar utilidades PKCS#11 / OpenSSL para inspección y exportación de llaves PEM
RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y --no-install-recommends \
    libc6:i386 \
    libstdc++6:i386 \
    libgcc-s1:i386 \
    opensc \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Crear estructura oficial de directorios Utimaco
RUN mkdir -p /opt/utimaco/sim5_linux \
             /opt/utimaco/admin \
             /usr/lib/utimaco \
             /etc/utimaco \
             /exported-keys

# 1. Copiar el Simulador Oficial Utimaco (bl_sim5 + memoria FLASH/NVRAM/SDRAM/MK)
COPY libs/Software/Linux/Simulator/sim5_linux/ /opt/utimaco/sim5_linux/

# 2. Copiar las herramientas oficiales de Administración Utimaco (csadm, p11tool2, cxitool, ADMIN.key)
COPY libs/Software/Linux/Administration/csadm /usr/local/bin/csadm
COPY libs/Software/Linux/Administration/p11tool2 /usr/local/bin/p11tool2
COPY libs/Software/Linux/Administration/cxitool /usr/local/bin/cxitool
COPY libs/Software/Linux/Administration/key/ /opt/utimaco/admin/key/

# 3. Copiar el Driver Oficial PKCS#11 R3 de Utimaco (libcs_pkcs11_R3.so)
COPY libs/Software/Linux/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so /usr/lib/utimaco/libcs_pkcs11_R3.so

# 4. Copiar configuración PKCS#11 R3 y script de arranque/aprovisionamiento Fase 0
COPY docker/utimaco-sim/cs_pkcs11_R3.cfg /etc/utimaco/cs_pkcs11_R3.cfg
COPY docker/utimaco-sim/init-hsm-keys.sh /usr/local/bin/init-hsm-keys.sh

RUN chmod +x /opt/utimaco/sim5_linux/bin/bl_sim5 \
             /opt/utimaco/sim5_linux/bin/cs_sim.sh \
             /usr/local/bin/csadm \
             /usr/local/bin/p11tool2 \
             /usr/local/bin/cxitool \
             /usr/lib/utimaco/libcs_pkcs11_R3.so \
             /usr/local/bin/init-hsm-keys.sh

ENV SDK_PORT=$SimulatorPort
ENV CRYPTOSERVER=${SimulatorPort}@127.0.0.1
ENV CS_PKCS11_R3_CFG=/etc/utimaco/cs_pkcs11_R3.cfg

WORKDIR /opt/utimaco/sim5_linux/bin
EXPOSE $SimulatorPort 3016
STOPSIGNAL SIGINT

ENTRYPOINT ["/usr/local/bin/init-hsm-keys.sh"]
CMD ["-o", "-h"]
