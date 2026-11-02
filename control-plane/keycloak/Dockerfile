# Keycloak with the federation's terms step (providers/terms) and login theme
# (themes/federation). Built by docker compose; the AWS deployment builds the same.
#
# The provider is compiled against Keycloak 26.4.7 (providers/terms/pom.xml). Keep the
# image's minor version (26.4) and the pom's in step.
FROM maven:3.9-eclipse-temurin-21 AS terms
WORKDIR /src
COPY providers/terms/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY providers/terms/src ./src
RUN mvn -q -B package

FROM quay.io/keycloak/keycloak:26.4
COPY --from=terms /src/target/federation-terms.jar /opt/keycloak/providers/
COPY themes/ /opt/keycloak/themes/
