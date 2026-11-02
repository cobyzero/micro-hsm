#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# FASE 0: Arranque del Simulador Oficial Utimaco (bl_sim5 v6.6.0.0) e
# inicialización de usuarios PKCS#11 y llaves transaccionales:
#   1. Levanta bl_sim5 en el puerto $SDK_PORT (por defecto 3015).
#   2. Autentica con csadm y ADMIN.key de fábrica de Utimaco.
#   3. Inicializa el Slot 0 con p11tool2 (SO_0000 y USR_0000 / Crypto Officer).
#   4. Genera el par RSA-2048 (PIN_E2E_RSA_2048) y la LMK AES-128 (LMK_PIN_AES_128).
#   5. Exporta la Llave Pública RSA en formato X.509 / PEM en /exported-keys.
# ==============================================================================

export SDK_PORT="${SDK_PORT:-3015}"
export CRYPTOSERVER="${CRYPTOSERVER:-${SDK_PORT}@127.0.0.1}"
export CS_PKCS11_R3_CFG="${CS_PKCS11_R3_CFG:-/etc/utimaco/cs_pkcs11_R3.cfg}"

PKCS11_MODULE="/usr/lib/utimaco/libcs_pkcs11_R3.so"
ADMIN_KEY="/opt/utimaco/admin/key/ADMIN.key"
SO_PIN="${HSM_SO_PIN:-12345678}"
CO_PIN="${HSM_CRYPTO_OFFICER_PIN:-12345678}"
TOKEN_LABEL="UTIMACO_PAYMENT_SLOT"
RSA_LABEL="${HSM_RSA_KEY_LABEL:-PIN_E2E_RSA_2048}"
LMK_LABEL="${HSM_LMK_KEY_LABEL:-LMK_PIN_AES_128}"
EXPORT_DIR="/exported-keys"

mkdir -p "$EXPORT_DIR"

# Crear un archivo cs_pkcs11_R3.cfg local para el contenedor del simulador apuntando a $CRYPTOSERVER
cat << EOF > /etc/utimaco/cs_pkcs11_R3_local.cfg
[Global]
Logging = 1
Logpath = /tmp
Logsize = 10mb
SlotMultiSession = true
SlotLoginRestriction = true
SlotCount = 10
KeepLeadZeros = false
FallbackInterval = 0
KeepAlive = true
ConnectionTimeout = 5000
CommandTimeout = 60000
KeysExternal = false

[HSMCluster]
Devices = ${CRYPTOSERVER}
EOF
export CS_PKCS11_R3_CFG=/etc/utimaco/cs_pkcs11_R3_local.cfg

echo "[UTIMACO-SIM] Iniciando demonio oficial Utimaco SecurityServer Simulator v6.6.0.0 (bl_sim5)..."
cd /opt/utimaco/sim5_linux/bin
if [ "$#" -gt 0 ]; then
    ./bl_sim5 "$@" &
else
    ./bl_sim5 -o -h &
fi
SIM_PID=$!

# Reenviar SIGINT/SIGTERM limpiamente a bl_sim5 (según STOPSIGNAL SIGINT de la guía oficial Utimaco)
trap 'echo "[UTIMACO-SIM] Deteniendo bl_sim5 (SIGINT)..."; kill -SIGINT "$SIM_PID" 2>/dev/null || true; wait "$SIM_PID" 2>/dev/null || true; exit 0' SIGINT SIGTERM

# Esperar a que el simulador Utimaco responda al comando oficial csadm GetState
echo "[UTIMACO-SIM] Esperando a que el HSM responda en $CRYPTOSERVER..."
for i in {1..30}; do
    if csadm Dev="$CRYPTOSERVER" GetState >/dev/null 2>&1; then
        echo "[UTIMACO-SIM] Simulador Utimaco en línea:"
        csadm Dev="$CRYPTOSERVER" GetState
        break
    fi
    sleep 1
done

# Verificar si el Slot 0 ya tiene la llave RSA generada
if ! pkcs11-tool --module "$PKCS11_MODULE" --slot 0 --list-objects 2>/dev/null | grep -q "$RSA_LABEL"; then
    echo "[UTIMACO-SIM] Inicializando Slot 0 con herramientas oficiales Utimaco (csadm + p11tool2)..."

    # Limpiar usuarios previos del Slot 0 si existieran (según setup_device.sh oficial de Utimaco)
    csadm Dev="$CRYPTOSERVER" LogonSign="ADMIN,$ADMIN_KEY" DeleteUser=USR_0000 DeleteUser=SO_0000 >/dev/null 2>&1 || true

    # Crear Security Officer (SO_0000) e inicializar el Token en Slot 0
    p11tool2 Login="ADMIN,$ADMIN_KEY" Force=1 Label="$TOKEN_LABEL" InitToken="$SO_PIN"

    # Crear Crypto Officer / User (USR_0000) con su PIN
    p11tool2 LoginSO="$SO_PIN" InitPin="$CO_PIN"

    echo "[UTIMACO-SIM] Generando par de llaves RSA-2048 ($RSA_LABEL) y certificado X.509 dentro del HSM Utimaco..."
    pkcs11-tool --module "$PKCS11_MODULE" \
        --slot 0 \
        --login --pin "$CO_PIN" \
        --keypairgen \
        --key-type rsa:2048 \
        --id 01 \
        --label "$RSA_LABEL" \
        --usage-decrypt \
        --usage-sign

    echo "[UTIMACO-SIM] Exportando Llave Pública RSA en formato X.509 / PEM..."
    pkcs11-tool --module "$PKCS11_MODULE" \
        --slot 0 \
        --read-object --type pubkey --label "$RSA_LABEL" \
        -o "$EXPORT_DIR/pin_e2e_rsa_pub.der"

    openssl rsa -pubin -inform DER -in "$EXPORT_DIR/pin_e2e_rsa_pub.der" \
        -outform PEM -out "$EXPORT_DIR/pin_e2e_rsa_pub.pem"

    echo "[UTIMACO-SIM] Generando llave maestra local LMK AES-128 ($LMK_LABEL) dentro del HSM Utimaco..."
    pkcs11-tool --module "$PKCS11_MODULE" \
        --slot 0 \
        --login --pin "$CO_PIN" \
        --keygen \
        --key-type aes:16 \
        --id 02 \
        --label "$LMK_LABEL"

    echo "[UTIMACO-SIM] Llave Pública exportada exitosamente en $EXPORT_DIR/pin_e2e_rsa_pub.pem:"
    cat "$EXPORT_DIR/pin_e2e_rsa_pub.pem"
else
    echo "[UTIMACO-SIM] El Slot 0 y las llaves ($RSA_LABEL / $LMK_LABEL) ya están inicializados en la NVRAM del simulador."
fi

echo "[UTIMACO-SIM] Simulador Oficial Utimaco v6.6.0.0 listo y escuchando en el puerto ${SDK_PORT}."
wait "$SIM_PID"
