# nginx-ldap-auth-python

A lightweight Python service to enable **LDAP authentication** behind **nginx**, useful for securing dashboards such as **Prometheus**, **Alertmanager**, and others that lack native auth support.

This script is inspired by [nginxinc/nginx-ldap-auth](https://github.com/nginxinc/nginx-ldap-auth) project.

---

## Features

- Connects to one or more LDAP servers (e.g., FreeIPA)
- Authenticates users using LDAP credentials
- Validates group membership before access is granted
- Works seamlessly with nginx's `auth_request` module
- No need to configure a BIND user

---

This repo provides the python script as it is and also the compiled version of the script to make it easier to port.
The python_ldap_auth_nginx.service file provides an example for a systemd service.
