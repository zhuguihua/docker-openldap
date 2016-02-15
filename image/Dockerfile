# Use osixia/light-baseimage
# sources: https://github.com/osixia/docker-light-baseimage
FROM osixia/light-baseimage:0.3.0
MAINTAINER Bertrand Gouny <bertrand.gouny@osixia.net>

# Add openldap user and group first to make sure their IDs get assigned consistently, regardless of whatever dependencies get added
RUN addgroup openldap && adduser -S openldap -G openldap

# Install OpenLDAP, ldap-utils and cfssl from baseimage
# sources: https://github.com/osixia/docker-light-baseimage/blob/stable/image/tool/add-service-available
#          https://github.com/osixia/docker-light-baseimage/blob/stable/image/service-available/:cfssl/download.sh
RUN apk update \
    && /container/tool/add-service-available :cfssl \
	  && apk add \
       openldap \
       openldap-back-bdb \
       openldap-back-hdb \
       openldap-clients \
       openldap-mqtt \
       openssl \
    && rm -rf /var/cache/apk/*

# Add service directory to /container/service
ADD service /container/service

# Use baseimage install-service script and clean all
# https://github.com/osixia/docker-light-baseimage/blob/stable/image/tool/install-service
RUN /container/tool/install-service

# Add default env variables
ADD environment /container/environment/99-default

# Set OpenLDAP data and config directories in a data volume
VOLUME ["/var/lib/ldap", "/etc/ldap/slapd.d"]

# Expose default ldap and ldaps ports
EXPOSE 389 636
