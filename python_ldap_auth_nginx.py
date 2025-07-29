from flask import Flask, request, Response
from ldap3 import Server, Connection, ALL, SUBTREE
from cachetools import TTLCache
import base64
import os

app = Flask(__name__)

LDAP_SERVERS = os.environ.get('LDAP_SERVERS').split(',')
BASE_DN = os.environ.get('BASE_DN')
GROUP_DN = os.environ.get('GROUP_DN')

auth_cache = TTLCache(maxsize=1000, ttl=6000)

def cache_key(username, password):
    return f"{username}:{password}"

def find_user_dn(server_url, username):
    server = Server(server_url, get_info=ALL)
    conn = Connection(server)
    if not conn.bind():
        print(f"[{server_url}] Anonymous bind failed")
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
        return Response(
            'Missing credentials',
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="Prometheus Login"'}
        )

    try:
        credentials = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
        username, password = credentials.split(':', 1)
    except Exception as e:
        print(f"Invalid Authorization header: {e}")
        return Response(
            'Invalid credentials',
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="Prometheus Login"'}
        )

    key = cache_key(username, password)
    if key in auth_cache:
        print(f"[CACHE HIT] Auth for {username}")
        return Response('Authenticated', status=200)

    for ldap_url in LDAP_SERVERS:
        print(f"Trying LDAP server: {ldap_url}")
        server, user_dn = find_user_dn(ldap_url, username)
        if not user_dn:
            continue

        try:
            conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            print(f"Authenticated via {ldap_url} as {user_dn}")

            if is_user_in_group(conn, user_dn):
                auth_cache[key] = user_dn
                conn.unbind()
                return Response('Authenticated', status=200)
            else:
                print(f"User {user_dn} not in group {GROUP_DN}")
                conn.unbind()
                return Response(
                    'Forbidden',
                    status=403,
                    headers={'WWW-Authenticate': 'Basic realm="Prometheus Login"'}
                )

        except Exception as e:
            print(f"Bind failed on {ldap_url} for {user_dn}: {e}")
            continue

    return Response(
        'Unauthorized',
        status=401,
        headers={'WWW-Authenticate': 'Basic realm="Prometheus Login"'}
    )

if __name__ == '__main__':
    port = int(os.getenv("PORT", 9000))
    app.run(host='0.0.0.0', port=port)
