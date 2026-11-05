#!/bin/sh
#
# Mitigacion de CVE-2026-91403 (OpenJDK advisory 2026-10-21, Oracle Security Alert).
#
# Ocho certificados intermedios de eMudhra (16 huellas SHA-256, contando las
# variantes de firma) tienen claves comprometidas y el JDK sigue confiando en
# ellos. La correccion oficial es anadirlos a la lista de bloqueo del JDK:
#
#   JDK 11+ : $JAVA_HOME/lib/security/blocked.certs
#   JDK 8   : $JAVA_HOME/jre/lib/security/blacklisted.certs
#
# Este script hace lo mismo que el comando manual del advisory, pero:
#   - es idempotente: si el JDK base ya trae las huellas (JDK corregido), no
#     duplica nada;
#   - parchea todos los ficheros de bloqueo que encuentre bajo $JAVA_HOME;
#   - FALLA la construccion si no puede dejar las 16 huellas aplicadas, en vez
#     de publicar una imagen sin parchear.
#
# Se puede quitar de los Dockerfile cuando la imagen base ya sea un JDK
# corregido (p. ej. Temurin 25.0.5.0.2 / 17.0.21+9 o posterior).
#
# Fuente de las huellas: advisory de OpenJDK 2026/10/21. Verificalas contra
# https://openjdk.org/groups/vulnerability/advisories/2026-10-21

set -eu

: "${JAVA_HOME:?JAVA_HOME no esta definido}"

FINGERPRINTS="
42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B
5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699
E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838
579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512
0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19
62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72
CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489
432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3
FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F
9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4
A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8
4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1
84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD
"

log() { printf '[block-emudhra-certs] %s\n' "$*"; }
die() { printf '[block-emudhra-certs] ERROR: %s\n' "$*" >&2; exit 1; }

# 1) Localizar los ficheros de bloqueo existentes (blocked.certs en 11+,
#    blacklisted.certs en 8). Puede haber varios (lib/ y jre/lib/).
TARGETS="$(find "$JAVA_HOME" \( -name blocked.certs -o -name blacklisted.certs \) -type f 2>/dev/null | sort)"

# 2) Si no existe ninguno, crearlo donde el JDK lo busca (igual que el
#    advisory: mkdir -p + cat >>).
if [ -z "$TARGETS" ]; then
    if [ -d "$JAVA_HOME/jre/lib/security" ]; then
        new="$JAVA_HOME/jre/lib/security/blacklisted.certs"      # JDK 8
    elif [ -d "$JAVA_HOME/lib/security" ]; then
        new="$JAVA_HOME/lib/security/blocked.certs"              # JDK 9+
    else
        die "no encuentro lib/security dentro de JAVA_HOME=$JAVA_HOME"
    fi
    log "no existia lista de bloqueo, creando $new"
    printf 'Algorithm=SHA-256\n' > "$new"
    TARGETS="$new"
fi

# 3) Anadir solo las huellas que falten.
for f in $TARGETS; do
    grep -qi '^[[:space:]]*Algorithm[[:space:]]*=[[:space:]]*SHA-256' "$f" \
        || die "$f no declara Algorithm=SHA-256; no lo modifico (formato inesperado)"

    # Asegurar salto de linea final antes de anadir.
    if [ -s "$f" ] && [ "$(tail -c1 "$f" | wc -l)" -eq 0 ]; then
        printf '\n' >> "$f"
    fi

    added=0
    for fp in $FINGERPRINTS; do
        if ! grep -qiE "^[[:space:]]*${fp}[[:space:]]*\$" "$f"; then
            printf '%s\n' "$fp" >> "$f"
            added=$((added + 1))
        fi
    done
    log "$f: $added huella(s) anadida(s), $((16 - added)) ya estaban"
done

# 4) Verificacion final: cada huella debe estar en TODOS los ficheros tocados.
for f in $TARGETS; do
    for fp in $FINGERPRINTS; do
        grep -qiE "^[[:space:]]*${fp}[[:space:]]*\$" "$f" \
            || die "falta la huella $fp en $f"
    done
done

log "OK: 16 huellas de eMudhra bloqueadas (CVE-2026-91403)"
