# Use osixia/light-baseimage
# sources: https://github.com/osixia/docker-light-baseimage
FROM osixia/alpine-light-baseimage:0.1.0
MAINTAINER Bertrand Gouny <bertrand.gouny@osixia.net>

# Add openldap user and group first to make sure their IDs get assigned consistently, regardless of whatever dependencies get added
RUN addgroup ldap && adduser -S ldap -G ldap

# Install OpenLDAP, ldap-utils and ssl-tools from baseimage and clean apt-get files
# sources: https://github.com/osixia/docker-light-baseimage/blob/stable/image/tool/add-service-available
#          https://github.com/osixia/docker-light-baseimage/blob/stable/image/service-available/:ssl-tools/download.sh
RUN apk update \
    && /container/tool/add-service-available :ssl-tools \
	  && apk add \
       openldap \
       openldap-back-bdb \
       openldap-back-hdb \
       openldap-clients \
       openldap-mqtt \
       openssl \
       slapd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Add service directory to /container/service
ADD service /container/service

# Use baseimage install-service script
# https://github.com/osixia/docker-light-baseimage/blob/stable/image/tool/install-service
RUN /container/tool/install-service

# Add default env variables
ADD environment /container/environment/99-default

# Expose default ldap and ldaps ports
EXPOSE 389 636
