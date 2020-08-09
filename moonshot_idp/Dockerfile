FROM jiscmoonshot/idp

RUN apt-get install -y python3-requests
COPY radsec.conf /etc/radsec.conf
COPY moonshot_ecp /etc/freeradius/mods-available
COPY moonshot_ecp.py /etc/freeradius/mods-config/python3
COPY inner-tunnel /etc/freeradius/sites-available/
RUN set -x \
    && ln -s /etc/freeradius/mods-available/moonshot_ecp /etc/freeradius/mods-enabled \
    && chown freerad /etc/freeradius/certs -R \
    && rm -f /etc/freeradius/mods-enabled/abfab_idp \
    && rm -f /etc/freeradius/sites-enabled/abfab-tls \
    && rm -f /etc/freeradius/sites-enabled/abfab-tr-idp
CMD freeradius -fxx -lstdout
