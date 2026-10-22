#!/usr/bin/env python3
"""Standalone S4NA-inspired catalogue and administration. Python 3.11+."""
import argparse, getpass, hashlib, hmac, ipaddress, json, mimetypes, os, re, secrets, sqlite3, threading, time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, unquote, quote

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('DATA_DIR', str(ROOT / 'data'))).resolve()
PUBLIC = ROOT / 'public'
ORIGIN = os.environ.get('PUBLIC_ORIGIN', 'http://localhost:8000').rstrip('/')
MAX_UPLOAD = int(os.environ.get('MAX_UPLOAD_MB', '100')) * 1024 * 1024
CATEGORIES = ['ARMES','AUTRES','BASES','BUNDLES','DUMPS','LOADING SCREEN','MAPPINGS','PACK GRAPHIQUE','SCRIPTS','TEMPLATE DISCORD','VEHICLES','VETEMENTS','FLASHBACK / FLASHFA','VIP']
RATE = {}; RATE_LOCK = threading.Lock()

def connect():
    db = sqlite3.connect(DATA / 'site.sqlite', timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def init():
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / 'files').mkdir(exist_ok=True)
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', banned INTEGER NOT NULL DEFAULT 0, vip INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, owner INTEGER NOT NULL REFERENCES users(id), created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS resources(id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL, cover TEXT NOT NULL DEFAULT '', file_id TEXT REFERENCES files(id), vip INTEGER NOT NULL DEFAULT 0, published INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0, views INTEGER NOT NULL DEFAULT 0, downloads INTEGER NOT NULL DEFAULT 0, author INTEGER NOT NULL REFERENCES users(id), created INTEGER NOT NULL, updated INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS favorites(user_id INTEGER NOT NULL REFERENCES users(id), resource_id INTEGER NOT NULL REFERENCES resources(id), PRIMARY KEY(user_id,resource_id));
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor INTEGER REFERENCES users(id), action TEXT NOT NULL, detail TEXT NOT NULL, created INTEGER NOT NULL);
        ''')
        for k,v in {'site_name':'S4NA — Mon catalogue','tagline':'Les meilleures ressources FiveM, au même endroit.','description':'Scripts, bases, mappings, véhicules et packs pour ta communauté.','discord_url':'','registration_open':'1'}.items():
            db.execute('INSERT OR IGNORE INTO settings VALUES(?,?)',(k,v))
        db.execute('DELETE FROM sessions WHERE expires<?',(int(time.time()),))

def password_hash(password):
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000)
    return salt.hex()+':'+digest.hex()

def verify_password(password,stored):
    salt,digest=stored.split(':')
    candidate=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),600000)
    return hmac.compare_digest(candidate,bytes.fromhex(digest))

DUMMY_HASH = None

def public_user(u):
    return {k:u[k] for k in ['id','email','name','role','banned','vip','created']}

def audit(db,actor,action,detail):
    db.execute('INSERT INTO audit(actor,action,detail,created) VALUES(?,?,?,?)',(actor,action,str(detail)[:2000],int(time.time())))

def text(value,limit,required=True):
    if not isinstance(value,str) or len(value)>limit or (required and not value.strip()):
        raise ValueError('Champ absent ou trop long.')
    return value.strip()

def email(value):
    v=text(value,254).lower()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',v): raise ValueError('Adresse e-mail invalide.')
    return v

def valid_password(value):
    if not isinstance(value,str) or not 12<=len(value)<=256: raise ValueError('Mot de passe : 12 à 256 caractères.')
    return value

def url(value):
    value=text(value,2000,False)
    if value and (urlsplit(value).scheme!='https' or not urlsplit(value).hostname or urlsplit(value).username):
        raise ValueError('Utilise une URL HTTPS complète.')
    return value

class Error(Exception):
    def __init__(self,status,message):self.status=status;self.message=message

class Handler(BaseHTTPRequestHandler):
    server_version='Catalogue'
    def log_message(self,fmt,*args):
        # Do not log query strings or credentials.
        print('%s %s %s' % (self.address_string(),self.command,self.path.split('?')[0]))
    def end_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','same-origin')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' https: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        super().end_headers()
    def reply(self,value,status=200,cookie=None):
        body=json.dumps(value,ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(body)))
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(body)
    def session(self,db,required=False,admin=False):
        try:
            c=SimpleCookie(self.headers.get('Cookie','')); token=c['session'].value if 'session' in c else ''
        except Exception: token=''
        row=db.execute('SELECT users.*,sessions.csrf,sessions.token AS session_token FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()
        if row and row['banned']:raise Error(403,'Compte suspendu.')
        if required and not row:raise Error(401,'Connecte-toi pour continuer.')
        if admin and (not row or row['role']!='admin'):raise Error(403,'Accès administrateur requis.')
        return row
    def csrf(self,u):
        if not u or not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),u['csrf']):
            raise Error(403,'Session expirée ou jeton de sécurité invalide. Recharge la page.')
    def body(self):
        if self.headers.get_content_type()!='application/json':raise Error(415,'JSON requis.')
        length=int(self.headers.get('Content-Length','0'))
        if length<=0 or length>128*1024:raise Error(413,'Requête trop volumineuse.')
        obj=json.loads(self.rfile.read(length))
        if not isinstance(obj,dict):raise ValueError('Objet JSON requis.')
        return obj
    def cookie(self,token='',clear=False):
        return 'session='+token+'; Path=/; HttpOnly; SameSite=Strict; Max-Age='+('0' if clear else '43200')+('; Secure' if ORIGIN.startswith('https://') else '')
    def rate_limit(self):
        now=time.time();key=self.client_address[0]
        if os.environ.get('TRUST_PROXY')=='1' and key in ('127.0.0.1','::1'):
            forwarded=self.headers.get('X-Forwarded-For','').split(',')[-1].strip()
            if forwarded:
                try:key=str(ipaddress.ip_address(forwarded))
                except ValueError:pass
        with RATE_LOCK:
            values=[t for t in RATE.get(key,[]) if t>now-900]
            if len(values)>=12:raise Error(429,'Trop de tentatives. Réessaie dans 15 minutes.')
            if len(RATE)>10000:RATE.clear()
            RATE[key]=values+[now]
    def dispatch(self,method):
        try:
            if self.headers.get('Host','').lower()!=urlsplit(ORIGIN).netloc.lower():raise Error(400,'Hôte non autorisé : vérifie PUBLIC_ORIGIN.')
            if method!='GET' and self.headers.get('Origin','')!=ORIGIN:raise Error(403,'Origine non autorisée.')
            path=urlsplit(self.path).path
            with connect() as db:
                if method=='GET':return self.get(db,path)
                return self.post(db,path)
        except Error as e:self.reply({'error':e.message},e.status)
        except (ValueError,KeyError,TypeError,UnicodeError,json.JSONDecodeError):self.reply({'error':'Données invalides. Vérifie les champs.'},400)
        except sqlite3.IntegrityError:self.reply({'error':'Cette opération est impossible ou cette adresse est déjà utilisée.'},409)
        except (BrokenPipeError,ConnectionResetError):pass
        except Exception as e:
            print('Server error:',type(e).__name__)
            self.reply({'error':'Erreur interne. Consulte les journaux du serveur.'},500)
    def do_GET(self):self.dispatch('GET')
    def do_POST(self):self.dispatch('POST')
    def get(self,db,path):
        if path=='/api/me':
            u=self.session(db);return self.reply({'user':public_user(u) if u else None,'csrf':u['csrf'] if u else None})
        if path=='/api/settings':return self.reply(dict(db.execute('SELECT key,value FROM settings').fetchall()))
        if path=='/api/resources':
            return self.reply({'resources':[dict(r) for r in db.execute('SELECT resources.*,users.name AS author_name,files.name AS file_name,files.size AS file_size FROM resources JOIN users ON author=users.id LEFT JOIN files ON file_id=files.id WHERE published=1 AND deleted=0 ORDER BY resources.id DESC')]})
        if path=='/api/favorites':
            u=self.session(db,True)
            return self.reply({'ids':[r[0] for r in db.execute('SELECT resource_id FROM favorites WHERE user_id=?',(u['id'],))]})
        if path.startswith('/api/download/'):
            u=self.session(db,True);rid=int(path.rsplit('/',1)[1])
            r=db.execute('SELECT resources.*,files.name AS file_name FROM resources LEFT JOIN files ON resources.file_id=files.id WHERE resources.id=?',(rid,)).fetchone()
            if not r or r['deleted'] or (not r['published'] and u['role']!='admin'):raise Error(404,'Ressource introuvable.')
            if r['vip'] and not u['vip'] and u['role']!='admin':raise Error(403,'Accès VIP requis.')
            if not r['file_id']:raise Error(404,'Aucun fichier joint.')
            file=DATA/'files'/r['file_id']
            if not file.is_file():raise Error(404,'Fichier indisponible.')
            db.execute('UPDATE resources SET downloads=downloads+1 WHERE id=?',(rid,));db.commit()
            self.send_response(200);self.send_header('Content-Type','application/octet-stream');self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(r['file_name'],safe=''));self.send_header('Content-Length',str(file.stat().st_size));self.send_header('Cache-Control','private, no-store');self.end_headers()
            with file.open('rb') as f:
                while chunk:=f.read(1024*1024):self.wfile.write(chunk)
            return
        if path=='/api/admin':
            self.session(db,True,True)
            users=[public_user(r) for r in db.execute('SELECT * FROM users ORDER BY id DESC')]
            rows=[dict(r) for r in db.execute('SELECT resources.*,users.name AS author_name,files.name AS file_name,files.size AS file_size FROM resources JOIN users ON author=users.id LEFT JOIN files ON file_id=files.id ORDER BY resources.id DESC')]
            logs=[dict(r) for r in db.execute('SELECT audit.*,users.name AS actor_name FROM audit LEFT JOIN users ON audit.actor=users.id ORDER BY audit.id DESC LIMIT 100')]
            return self.reply({'users':users,'resources':rows,'settings':dict(db.execute('SELECT key,value FROM settings').fetchall()),'logs':logs,'categories':CATEGORIES,'max_upload_mb':MAX_UPLOAD//1024//1024})
        if path.startswith('/api/'):raise Error(404,'Route inconnue.')
        if path in ('/admin','/admin/'):
            u=self.session(db)
            path='/admin.html' if u and u['role']=='admin' else '/index.html'
        if path=='/':path='/index.html'
        file=(PUBLIC/unquote(path).lstrip('/')).resolve()
        if PUBLIC.resolve() not in file.parents or not file.is_file():raise Error(404,'Page introuvable.')
        body=file.read_bytes();self.send_response(200);self.send_header('Content-Type',(mimetypes.guess_type(file.name)[0] or 'application/octet-stream')+('; charset=utf-8' if file.suffix in ['.html','.js','.css'] else ''));self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-cache');self.end_headers();self.wfile.write(body)
    def post(self,db,path):
        if path in ('/api/login','/api/register'):
            self.rate_limit();p=self.body();mail=email(p.get('email'));pw=valid_password(p.get('password'))
            if path=='/api/register':
                if db.execute("SELECT value FROM settings WHERE key='registration_open'").fetchone()[0]!='1':raise Error(403,'Inscriptions fermées.')
                name=text(p.get('name'),60)
                db.execute('INSERT INTO users(email,name,password,created) VALUES(?,?,?,?)',(mail,name,password_hash(pw),int(time.time())))
            u=db.execute('SELECT * FROM users WHERE email=?',(mail,)).fetchone()
            valid=verify_password(pw,u['password'] if u else DUMMY_HASH)
            if not u or not valid:raise Error(401,'Identifiants incorrects.')
            if u['banned']:raise Error(403,'Compte suspendu.')
            token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
            db.execute('DELETE FROM sessions WHERE expires<?',(int(time.time()),))
            db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],csrf,int(time.time())+43200))
            audit(db,u['id'],'connexion','Connexion au compte');db.commit()
            return self.reply({'user':public_user(u),'csrf':csrf},cookie=self.cookie(token))
        u=self.session(db,True);self.csrf(u)
        if path=='/api/logout':
            db.execute('DELETE FROM sessions WHERE token=?',(u['session_token'],));db.commit();return self.reply({'ok':True},cookie=self.cookie(clear=True))
        if path=='/api/password':
            p=self.body()
            if not verify_password(valid_password(p.get('current')),u['password']):raise Error(403,'Mot de passe actuel incorrect.')
            db.execute('UPDATE users SET password=? WHERE id=?',(password_hash(valid_password(p.get('password'))),u['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],));audit(db,u['id'],'mot_de_passe','Mot de passe modifié');db.commit()
            return self.reply({'ok':True},cookie=self.cookie(clear=True))
        if path=='/api/favorites':
            p=self.body();rid=int(p['id'])
            if not db.execute('SELECT id FROM resources WHERE id=? AND published=1 AND deleted=0',(rid,)).fetchone():raise Error(404,'Ressource introuvable.')
            if p.get('saved'):db.execute('INSERT OR IGNORE INTO favorites VALUES(?,?)',(u['id'],rid))
            else:db.execute('DELETE FROM favorites WHERE user_id=? AND resource_id=?',(u['id'],rid))
            db.commit();return self.reply({'ok':True})
        if not path.startswith('/api/admin/'):raise Error(404,'Route inconnue.')
        if u['role']!='admin':raise Error(403,'Accès administrateur requis.')
        if path=='/api/admin/upload':
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=MAX_UPLOAD:raise Error(413,'Fichier trop volumineux ou vide.')
            name=text(unquote(self.headers.get('X-Filename','fichier.zip')),200)
            name=name.replace('\\','/').split('/')[-1]
            if not name or any(ord(c)<32 for c in name):raise ValueError('Nom invalide.')
            fid=secrets.token_hex(24);tmp=DATA/'files'/(fid+'.part');final=DATA/'files'/fid
            try:
                self.connection.settimeout(120)
                with tmp.open('xb') as out:
                    remaining=length
                    while remaining:
                        chunk=self.rfile.read(min(1024*1024,remaining))
                        if not chunk:raise ValueError('Upload interrompu.')
                        out.write(chunk);remaining-=len(chunk)
                tmp.rename(final)
                db.execute('INSERT INTO files VALUES(?,?,?,?,?)',(fid,name,length,u['id'],int(time.time())))
                audit(db,u['id'],'fichier_ajoute',name);db.commit()
            except Exception:
                tmp.unlink(missing_ok=True);final.unlink(missing_ok=True);raise
            return self.reply({'id':fid,'name':name,'size':length},201)
        p=self.body()
        if path=='/api/admin/resource':
            title=text(p.get('title'),180);description=text(p.get('description'),20000);category=text(p.get('category'),50)
            if category not in CATEGORIES:raise ValueError('Catégorie invalide.')
            cover=url(p.get('cover',''));fid=p.get('file_id') or None
            if fid and not db.execute('SELECT id FROM files WHERE id=?',(fid,)).fetchone():raise ValueError('Fichier absent.')
            published=1 if p.get('published') else 0
            if published and not fid:raise Error(400,'Joins un fichier avant de publier la ressource.')
            vals=(title,description,category,cover,fid,int(bool(p.get('vip'))),published)
            now=int(time.time());rid=p.get('id')
            if rid:
                if not db.execute('SELECT id FROM resources WHERE id=?',(int(rid),)).fetchone():raise Error(404,'Ressource introuvable.')
                db.execute('UPDATE resources SET title=?,description=?,category=?,cover=?,file_id=?,vip=?,published=?,updated=? WHERE id=?',(*vals,now,int(rid)))
            else:
                rid=db.execute('INSERT INTO resources(title,description,category,cover,file_id,vip,published,author,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)',(*vals,u['id'],now,now)).lastrowid
            audit(db,u['id'],'ressource_enregistree',str(rid)+' — '+title);db.commit();return self.reply({'id':rid})
        if path=='/api/admin/trash':
            rid=int(p['id']);deleted=1 if p.get('deleted') else 0
            if not db.execute('SELECT id FROM resources WHERE id=?',(rid,)).fetchone():raise Error(404,'Ressource introuvable.')
            db.execute('UPDATE resources SET deleted=?,updated=? WHERE id=?',(deleted,int(time.time()),rid))
            audit(db,u['id'],'corbeille' if deleted else 'restauration',rid);db.commit();return self.reply({'ok':True})
        if path=='/api/admin/user':
            uid=int(p['id']);role=p.get('role');banned=int(bool(p.get('banned')));vip=int(bool(p.get('vip')))
            if role not in ('admin','member'):raise ValueError('Rôle invalide.')
            target=db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
            if not target:raise Error(404,'Utilisateur introuvable.')
            if uid==u['id'] and (role!='admin' or banned):raise Error(400,'Tu ne peux pas retirer ton propre accès administrateur.')
            # Serialize the last-admin check and role update.
            db.execute('BEGIN IMMEDIATE')
            target=db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
            if target['role']=='admin' and not target['banned'] and (role!='admin' or banned):
                if db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND banned=0").fetchone()[0]<=1:raise Error(400,'Conserve au moins un administrateur actif.')
            db.execute('UPDATE users SET role=?,banned=?,vip=? WHERE id=?',(role,banned,vip,uid))
            if banned or role!=target['role']:db.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
            audit(db,u['id'],'utilisateur_modifie',f'{uid}: rôle={role}, suspendu={banned}, VIP={vip}');db.commit();return self.reply({'ok':True})
        if path=='/api/admin/settings':
            settings={'site_name':text(p.get('site_name'),80),'tagline':text(p.get('tagline'),180),'description':text(p.get('description'),1000),'discord_url':url(p.get('discord_url','')),'registration_open':'1' if p.get('registration_open') else '0'}
            for k,v in settings.items():db.execute('UPDATE settings SET value=? WHERE key=?',(v,k))
            audit(db,u['id'],'reglages','Réglages mis à jour');db.commit();return self.reply({'ok':True})
        raise Error(404,'Route inconnue.')

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def get_request(self):
        sock,addr=super().get_request();sock.settimeout(30);return sock,addr

def main():
    global DUMMY_HASH
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['serve','create-admin','reset-password','backup']);parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=8000);args=parser.parse_args();init()
    if args.command in ('create-admin','reset-password'):
        mail=email(input('Adresse e-mail : '));name=text(input('Nom : '),60) if args.command=='create-admin' else None
        pw=valid_password(getpass.getpass('Mot de passe (12 caractères minimum) : '))
        if pw!=getpass.getpass('Confirmer : '):raise SystemExit('Les mots de passe ne correspondent pas.')
        with connect() as db:
            if args.command=='create-admin':db.execute("INSERT INTO users(email,name,password,role,created) VALUES(?,?,?,'admin',?)",(mail,name,password_hash(pw),int(time.time())))
            else:
                u=db.execute('SELECT id FROM users WHERE email=?',(mail,)).fetchone()
                if not u:raise SystemExit('Compte introuvable.')
                db.execute('UPDATE users SET password=? WHERE id=?',(password_hash(pw),u['id']));db.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
        print('Compte mis à jour.');return
    if args.command=='backup':
        import zipfile,tempfile
        target=ROOT/('sauvegarde-'+time.strftime('%Y%m%d-%H%M%S')+'.zip')
        with tempfile.TemporaryDirectory() as temp:
            snapshot=Path(temp)/'site.sqlite'
            with connect() as source,sqlite3.connect(snapshot) as dest:source.backup(dest)
            with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
                z.write(snapshot,'data/site.sqlite')
                for f in (DATA/'files').iterdir():
                    if f.is_file() and not f.name.endswith('.part'):z.write(f,'data/files/'+f.name)
        print('Sauvegarde créée :',target.name);return
    if urlsplit(ORIGIN).scheme not in ('http','https') or urlsplit(ORIGIN).path or not urlsplit(ORIGIN).hostname:raise SystemExit('PUBLIC_ORIGIN invalide.')
    DUMMY_HASH=password_hash(secrets.token_urlsafe(32))
    print('Site : '+ORIGIN+' | Administration : '+ORIGIN+'/admin')
    print('Utilise un reverse proxy HTTPS pour un accès public. Ctrl+C pour arrêter.')
    Server((args.host,args.port),Handler).serve_forever()
if __name__=='__main__':main()
