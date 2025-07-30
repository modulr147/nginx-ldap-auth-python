# nginx-ldap-auth-python

A lightweight Python service to enable **LDAP authentication** behind **nginx**, useful for securing dashboards such as **Prometheus**, **Alertmanager**, and others that lack native auth support.

This script is inspired by [nginxinc/nginx-ldap-auth](https://github.com/nginxinc/nginx-ldap-auth) project.

**Python version used: 3.9**
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

## How to run it without compiling

1. Clone this repository
```
git clone https://github.com/modulr147/nginx-ldap-auth-python.git
```
3. Create a new VENV in python
```
python -m venv nginx_ldap_auth-python
```
3. Source the environment
```
source nginx_ldap_auth-python/bin/activate
```
4. Install dependencies
```
pip install flask ldap3 cachetools
```
5. Replace the below environment variables with your actual LDAP settings
In my case the domain is: `test.com` group is: `test-group` LDAP servers: `ldap://ldap1.test.com:389,ldap://ldap2.test.com:389`
```
GROUP_DN="cn=test-group,cn=groups,cn=accounts,dc=test,dc=com"
BASE_DN="cn=users,cn=accounts,dc=test,dc=com"
LDAP_SERVERS="ldap://ldap1.test.com:389,ldap://ldap2.test.com:389"
HOST_IP=127.0.0.1
PORT=9000
```
6. Run the python script
```
python python_ldap_auth_nginx.py
```
You should see the following if everythiong is OK:
```
2025-07-30 09:15:03,666 INFO [ldap-auth] Starting LDAP auth server on 0.0.0.0:9000
 * Serving Flask app 'python_ldap_auth_nginx'
 * Debug mode: off
2025-07-30 09:15:03,816 INFO [werkzeug] WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:9000
 * Running on http://192.168.110.25:9000
2025-07-30 09:15:03,817 INFO [werkzeug] Press CTRL+C to quit
```
