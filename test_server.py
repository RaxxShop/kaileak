"""Integration tests: isolated temporary database and real HTTP requests."""
import http.cookiejar, importlib.util, json, os, secrets, socket, subprocess, sys, tempfile, time, unittest
from pathlib import Path
from urllib.request import Request, build_opener, HTTPCookieProcessor
from urllib.error import HTTPError
ROOT=Path(__file__).resolve().parent

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();os.environ['DATA_DIR']=cls.temp.name
        sock=socket.socket();sock.bind(('127.0.0.1',0));cls.port=sock.getsockname()[1];sock.close()
        cls.origin=f'http://127.0.0.1:{cls.port}';os.environ['PUBLIC_ORIGIN']=cls.origin
        spec=importlib.util.spec_from_file_location('catalogue_server',ROOT/'server.py');cls.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.module);cls.module.init()
        cls.password=secrets.token_urlsafe(24)
        with cls.module.connect() as db:
            db.execute("INSERT INTO users(email,name,password,role,created) VALUES(?,?,?,'admin',?)",('admin@example.test','Admin',cls.module.password_hash(cls.password),int(time.time())))
        cls.process=subprocess.Popen([sys.executable,str(ROOT/'server.py'),'serve','--port',str(cls.port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=os.environ.copy())
        cls.anonymous=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()));cls.admin=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()));cls.member=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        for _ in range(60):
            try:
                with cls.anonymous.open(cls.origin+'/api/settings',timeout=1):break
            except OSError:time.sleep(.05)
        else:raise RuntimeError('Server did not start')
    @classmethod
    def tearDownClass(cls):cls.process.terminate();cls.process.wait(timeout=5);cls.temp.cleanup()
    def request(self,client,path,data=None,csrf=None,raw=None,origin=None):
        headers={'Origin':origin or self.origin}
        body=None
        if data is not None:headers['Content-Type']='application/json';body=json.dumps(data).encode()
        if csrf:headers['X-CSRF-Token']=csrf
        if raw is not None:body=raw;headers.update({'Content-Type':'application/octet-stream','X-Filename':'ressource-test.zip'})
        req=Request(self.origin+path,data=body,headers=headers)
        try:r=client.open(req,timeout=10)
        except HTTPError as e:r=e
        content=r.read()
        return r.status,json.loads(content) if r.headers.get_content_type()=='application/json' else content
    def test_lifecycle_and_security(self):
        status,_=self.request(self.anonymous,'/api/admin');self.assertEqual(status,401)
        status,_=self.request(self.anonymous,'/../data/site.sqlite');self.assertEqual(status,404)
        status,_=self.request(self.admin,'/api/login',{'email':'admin@example.test','password':self.password},origin='https://attacker.example');self.assertEqual(status,403)
        status,s=self.request(self.admin,'/api/login',{'email':'admin@example.test','password':self.password});self.assertEqual(status,200);csrf=s['csrf']
        status,_=self.request(self.admin,'/api/admin/settings',{});self.assertEqual(status,403)
        status,s=self.request(self.member,'/api/register',{'email':'member@example.test','password':self.password,'name':'Membre','role':'admin','vip':True});self.assertEqual(status,200);member_csrf=s['csrf'];uid=s['user']['id'];self.assertEqual(s['user']['role'],'member');self.assertEqual(s['user']['vip'],0)
        status,_=self.request(self.member,'/api/admin');self.assertEqual(status,403)
        status,_=self.request(self.member,'/api/admin/upload',csrf=member_csrf,raw=b'file');self.assertEqual(status,403)
        content=b'PK-test-file-contents'
        status,uploaded=self.request(self.admin,'/api/admin/upload',csrf=csrf,raw=content);self.assertEqual(status,201)
        r={'title':'Test resource','description':'Description','category':'SCRIPTS','file_id':uploaded['id'],'published':False,'vip':True}
        status,result=self.request(self.admin,'/api/admin/resource',r,csrf);self.assertEqual(status,200);rid=result['id'];r['id']=rid
        status,listing=self.request(self.anonymous,'/api/resources');self.assertEqual(len(listing['resources']),0)
        status,_=self.request(self.member,f'/api/download/{rid}');self.assertEqual(status,404)
        r['published']=True;self.request(self.admin,'/api/admin/resource',r,csrf)
        status,listing=self.request(self.anonymous,'/api/resources');self.assertEqual(len(listing['resources']),1)
        status,_=self.request(self.anonymous,f'/api/download/{rid}');self.assertEqual(status,401)
        status,_=self.request(self.member,f'/api/download/{rid}');self.assertEqual(status,403)
        status,_=self.request(self.admin,'/api/admin/user',{'id':uid,'role':'member','vip':True,'banned':False},csrf);self.assertEqual(status,200)
        status,body=self.request(self.member,f'/api/download/{rid}');self.assertEqual(status,200);self.assertEqual(body,content)
        self.request(self.member,'/api/favorites',{'id':rid,'saved':True},member_csrf)
        status,saved=self.request(self.member,'/api/favorites');self.assertEqual(saved['ids'],[rid])
        status,_=self.request(self.admin,'/api/admin/trash',{'id':rid,'deleted':True},csrf);self.assertEqual(status,200)
        status,_=self.request(self.member,f'/api/download/{rid}');self.assertEqual(status,404)
        self.request(self.admin,'/api/admin/trash',{'id':rid,'deleted':False},csrf)
        status,body=self.request(self.member,f'/api/download/{rid}');self.assertEqual(status,200)
        status,_=self.request(self.admin,'/api/admin/user',{'id':1,'role':'member','banned':False},csrf);self.assertEqual(status,400)
        status,_=self.request(self.admin,'/api/admin/user',{'id':uid,'role':'member','vip':True,'banned':True},csrf);self.assertEqual(status,200)
        status,_=self.request(self.member,f'/api/download/{rid}');self.assertEqual(status,401)
        status,_=self.request(self.member,'/api/login',{'email':'member@example.test','password':self.password});self.assertEqual(status,403)
        status,state=self.request(self.admin,'/api/admin');self.assertEqual(status,200);self.assertEqual(state['resources'][0]['downloads'],2);self.assertTrue(state['logs'])
        new_password=secrets.token_urlsafe(24)
        status,_=self.request(self.admin,'/api/password',{'current':self.password,'password':new_password},csrf);self.assertEqual(status,200)
        status,_=self.request(self.admin,'/api/admin');self.assertEqual(status,401)
        status,_=self.request(self.admin,'/api/login',{'email':'admin@example.test','password':new_password});self.assertEqual(status,200)
        status,_=self.request(self.admin,'/api/admin');self.assertEqual(status,200)
if __name__=='__main__':unittest.main(verbosity=2)
