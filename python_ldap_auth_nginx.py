from flask import Flask, request, Response, g
from ldap3 import Server, Connection, ALL, SUBTREE
from cachetools import TTLCache
import base64
import os
import logging

app = Flask(__name__)

LDAP_SERVERS = os.environ.get('LDAP_SERVERS', 'ldap://idm.example.com').split(',')
BASE_DN = os.environ.get('BASE_DN', 'cn=users,cn=accounts,dc=example,dc=com')
GROUP_DN = os.environ.get('GROUP_DN', 'cn=monitoring,cn=groups,cn=accounts,cn=accounts,dc=example,dc=com')

# cahe credentials for 1 hour
auth_cache = TTLCache(maxsize=10000, ttl=3600)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
)

logger = logging.getLogger("ldap-auth")

def cache_key(username, password):
    return f"{username}:{password}"

def find_user_dn(server_url, username):
    server = Server(server_url, get_info=ALL)
    conn = Connection(server)
    if not conn.bind():
        logger.warning(f"[{server_url}] Anonymous bind failed")
        return None, None

    search_filter = f'(uid={username})'
    conn.search(search_base=BASE_DN,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['dn'])

    if conn.entries:
        user_dn = conn.entries[0].entry_dn
        conn.unbind()
        return server, user_dn

    conn.unbind()
    return None, None

def is_user_in_group(conn, user_dn):
    conn.search(search_base=GROUP_DN,
                search_filter=f'(member={user_dn})',
                search_scope=SUBTREE,
                attributes=['member'])
    return bool(conn.entries)

@app.route('/auth', methods=['GET'])
def auth():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Basic '):
        logger.info(f"Missing Authorization header")
        return Response(
            'Missing credentials',
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="LDAP Login"'}
        )

    try:
        credentials = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
        username, password = credentials.split(':', 1)
    except Exception as e:
        logger.warning(f"Invalid Authorization header: {e}")
        return Response(
            'Invalid credentials',
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="LDAP Login"'}
        )

    key = cache_key(username, password)
    if key in auth_cache:
        logger.info(f"[LDAP CACHE HIT] Auth success for user: {username}")
        return Response('Authenticated', status=200)

    for ldap_url in LDAP_SERVERS:
        logger.info(f"Trying LDAP server: {ldap_url}")
        server, user_dn = find_user_dn(ldap_url, username)
        if not user_dn:
            logger.info(f"User {username} not found on {ldap_url}")
            continue

        try:
            conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            logger.info(f"Authenticated via {ldap_url} as {user_dn.split(',')[0].split('=')[1]}")

            if is_user_in_group(conn, user_dn):
                auth_cache[key] = user_dn
                conn.unbind()
                logger.info(f"User {user_dn.split(',')[0].split('=')[1]} authorized (in group {GROUP_DN.split(',')[0].split('=')[1]})")
                return Response('Authenticated', status=200)
            else:
                logger.warning(f"User {user_dn.split(',')[0].split('=')[1]} not in expected group. Expected group is {GROUP_DN.split(',')[0].split('=')[1]}.")
                conn.unbind()
                return Response(
                    'Forbidden',
                    status=403,
                    headers={'WWW-Authenticate': 'Basic realm="LDAP Login"'}
                )

        except Exception as e:
            logger.warning(f"Bind failed on {ldap_url} for {user_dn.split(',')[0].split('=')[1]}: {e}")
            continue

        logger.info(f"Unauthorized access attempt for user {username}")
    return Response(
        'Unauthorized',
        status=401,
        headers={'WWW-Authenticate': 'Basic realm="LDAP Login"'}
    )

if __name__ == '__main__':
    port = int(os.getenv("PORT", 9000))
    host = os.getenv("HOST_IP", "0.0.0.0")
    logger.info(f"Starting LDAP auth server on {host}:{port}")
    app.run(host=host, port=port)
