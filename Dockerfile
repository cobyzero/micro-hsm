# ==============================================================================
# Build Stage
# ==============================================================================
FROM --platform=linux/amd64 eclipse-temurin:21-jdk-jammy AS build
WORKDIR /app

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod +x mvnw && ./mvnw dependency:go-offline -B

COPY src ./src
RUN ./mvnw clean package -DskipTests -B

# ==============================================================================
# Runtime Stage (Con el Driver Oficial Utimaco v6.6.0.0 libcs_pkcs11_R3.so)
# ==============================================================================
FROM --platform=linux/amd64 eclipse-temurin:21-jre-jammy
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    opensc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/utimaco /usr/lib/utimaco

# Copiar el driver oficial PKCS#11 R3 de Utimaco v6.6.0.0 y el proveedor JCE oficial
COPY libs/Software/Linux/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so /usr/lib/utimaco/libcs_pkcs11_R3.so
COPY libs/Software/Linux/Crypto_APIs/JCE/lib/securityserver-jce.jar /usr/lib/utimaco/securityserver-jce.jar
COPY docker/utimaco-sim/cs_pkcs11_R3.cfg /etc/utimaco/cs_pkcs11_R3.cfg
COPY --from=build /app/target/micro-hsm-1.0.0.jar /app/micro-hsm.jar

RUN chmod +x /usr/lib/utimaco/libcs_pkcs11_R3.so

ENV CS_PKCS11_R3_CFG=/etc/utimaco/cs_pkcs11_R3.cfg
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/micro-hsm.jar"]
