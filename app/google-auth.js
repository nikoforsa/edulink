const crypto = require('node:crypto');
const random = () => crypto.randomBytes(32).toString('base64url');
async function googleJson(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error('Google request failed');
  return response.json();
}
async function verifyIdToken(token, audience, nonce, getKeys = () => googleJson('https://www.googleapis.com/oauth2/v3/certs')) {
  if (typeof token !== 'string' || token.length > 20000) throw new Error('Invalid token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  if (header.alg !== 'RS256' || !header.kid) throw new Error('Invalid algorithm');
  const { keys } = await getKeys();
  const jwk = keys.find(k => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk || !crypto.verify('RSA-SHA256', Buffer.from(parts.slice(0,2).join('.')), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'))) throw new Error('Invalid signature');
  const p = JSON.parse(Buffer.from(parts[1], 'base64url'));
  const now = Math.floor(Date.now()/1000);
  if (!['https://accounts.google.com','accounts.google.com'].includes(p.iss) || p.aud !== audience || (p.azp && p.azp !== audience) || !Number.isFinite(p.exp) || p.exp <= now || !Number.isFinite(p.iat) || p.iat > now+60 || p.nonce !== nonce || typeof p.sub !== 'string' || !p.sub || p.email_verified !== true || typeof p.email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(p.email)) throw new Error('Invalid claims');
  return p;
}
function validateLink(account, identity, flow, sessionToken, sessions) {
  const session = sessions.get(sessionToken);
  if (sessionToken !== flow.sessionToken || !session || session.accountId !== flow.accountId || !account || Number(account.id) !== flow.accountId || account.password_hash !== flow.passwordHash || account.status !== 'Активен' || account.locked_at || !account.email_verified) throw new Error('Link session invalid');
  if (identity.email.trim().toLowerCase() !== account.email.trim().toLowerCase()) throw new Error('Link email mismatch');
  if (account.google_sub && account.google_sub !== identity.sub) throw new Error('Already linked');
}
function create({ transaction, sessions, parseCookies, roleCode, hashPassword, syncRoleProfile, sendJson, readBody }) {
  const pending = new Map();
  const clientId = process.env.GOOGLE_CLIENT_ID, secret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || 'http://127.0.0.1:8000/api/auth/google/callback';
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const cookie = (value, age) => `edulink_oauth=${value}; HttpOnly; SameSite=Lax; Path=/api/auth/google; Max-Age=${age}${secure}`;
  const enabled = Boolean(clientId && secret && (process.env.NODE_ENV !== 'production' || redirectUri.startsWith('https://')));
  return async (req,res) => {
    const url = new URL(req.url,'http://localhost');
    if (!url.pathname.startsWith('/api/auth/google')) return false;
    const linking = req.method === 'POST' && url.pathname === '/api/auth/google/link';
    if (req.method !== 'GET' && !linking) { sendJson(res,405,{error:'Метод не поддерживается'}); return true; }
    if (url.pathname === '/api/auth/google/config') { sendJson(res,200,{enabled}); return true; }
    if (!enabled) { sendJson(res,503,{error:'Вход через Google ещё не настроен администратором'}); return true; }
    const redirect = (location, cookies) => { res.writeHead(302,{'Location':location,'Set-Cookie':cookies,'Cache-Control':'no-store','Referrer-Policy':'no-referrer'});res.end(); };
    if (url.pathname === '/api/auth/google/start' || linking) {
      for (const [s,p] of pending) if (p.expires < Date.now()) pending.delete(s);
      if (pending.size >= 1000) { sendJson(res,429,{error:'Повторите попытку позже'}); return true; }
      const state=random(), browser=random(), nonce=random(), verifier=random();
      const flow={browser,nonce,verifier,expires:Date.now()+600000};
      if (linking) {
        if (req.headers.origin !== new URL(redirectUri).origin || !String(req.headers['content-type']).startsWith('application/json')) { sendJson(res,403,{error:'Откройте приложение по адресу '+new URL(redirectUri).origin});return true; }
        const sessionToken=parseCookies(req).edulink_session, session=sessions.get(sessionToken);
        if(!session){sendJson(res,401,{error:'Сначала войдите по паролю'});return true;}
        if(session.googleLinkBlockedUntil>Date.now()){sendJson(res,429,{error:'Слишком много попыток. Повторите через 15 минут.'});return true;}
        const body=await readBody(req);
        const a=await transaction(async c=>(await c.query('SELECT * FROM accounts WHERE id=$1',[session.accountId])).rows[0]);
        const supplied=Buffer.from(a?hashPassword(String(body.password||''),a.password_salt):'');
        const expected=Buffer.from(a?.password_hash||'invalid');
        if(!a || a.status!=='Активен' || a.locked_at || !a.email_verified || supplied.length!==expected.length || !crypto.timingSafeEqual(supplied,expected)){
          session.googleLinkFailures=(session.googleLinkFailures||0)+1;
          if(session.googleLinkFailures>=5){session.googleLinkBlockedUntil=Date.now()+900000;session.googleLinkFailures=0;}
          sendJson(res,403,{error:'Проверьте текущий пароль и состояние учётной записи'});return true;
        }
        session.googleLinkFailures=0;
        Object.assign(flow,{accountId:Number(a.id),sessionToken,passwordHash:a.password_hash});
      }
      pending.set(state,flow);
      const params=new URLSearchParams({client_id:clientId,redirect_uri:redirectUri,response_type:'code',scope:'openid email profile',state,nonce,code_challenge:crypto.createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',prompt:'select_account'});
      const authorizationUrl='https://accounts.google.com/o/oauth2/v2/auth?'+params;
      if(linking)sendJson(res,200,{url:authorizationUrl},{'Set-Cookie':cookie(browser,600)});
      else redirect(authorizationUrl,cookie(browser,600));return true;
    }
    if (url.pathname !== '/api/auth/google/callback') { sendJson(res,404,{error:'Не найдено'});return true; }
    let errorCode='state', linkSession;
    try {
      const state=url.searchParams.get('state'), flow=pending.get(state);
      if (!flow || flow.expires<Date.now() || parseCookies(req).edulink_oauth!==flow.browser) throw new Error('Invalid state');
      pending.delete(state);
      linkSession=flow.sessionToken && sessions.get(flow.sessionToken);
      if (url.searchParams.has('error')) { errorCode='cancelled';throw new Error('Cancelled'); }
      const code=url.searchParams.get('code');if(!code)throw new Error('Missing code');
      errorCode='token';
      const token=await googleJson('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code,client_id:clientId,client_secret:secret,redirect_uri:redirectUri,grant_type:'authorization_code',code_verifier:flow.verifier})});
      errorCode='identity';
      const identity=await verifyIdToken(token.id_token,clientId,flow.nonce);
      const account=await transaction(async c=>{
        // Serializes first links and registration against other account mutations.
        await c.query('LOCK TABLE accounts IN SHARE ROW EXCLUSIVE MODE');
        let a=(await c.query('SELECT * FROM accounts WHERE google_sub=$1',[identity.sub])).rows[0];
        if (flow.accountId) {
          errorCode='link';
          if(a && Number(a.id)!==flow.accountId){errorCode='already_used';throw new Error('Google identity already used');}
          a=(await c.query('SELECT * FROM accounts WHERE id=$1',[flow.accountId])).rows[0];
          if(a && identity.email.trim().toLowerCase()!==a.email.trim().toLowerCase()){errorCode='email_mismatch';throw new Error('Wrong Google email');}
          validateLink(a,identity,flow,parseCookies(req).edulink_session,sessions);
        } else if (!a) {
          const email=identity.email.trim().toLowerCase();
          a=(await c.query('SELECT * FROM accounts WHERE lower(email)=$1',[email])).rows[0];
          if(a){
            // Google is authoritative for Gmail and verified Workspace addresses only.
            if(a.google_sub || !a.email_verified || !(email.endsWith('@gmail.com') || (typeof identity.hd==='string' && identity.hd))) { errorCode='link';throw new Error('Cannot link'); }
          }else{
            const salt=random();
            a=(await c.query("INSERT INTO accounts(name,email,role,status,password_hash,password_salt,email_verified,google_sub) VALUES($1,$2,'Студент','Активен',$3,$4,TRUE,$5) RETURNING *",[String(identity.name||email).slice(0,200),email,hashPassword(random(),salt),salt,identity.sub])).rows[0];
            await syncRoleProfile(Number(a.id),'Студент',c);
          }
        }
        if(a.status!=='Активен'||a.locked_at){errorCode='blocked';throw new Error('Inactive account');}
        await c.query('UPDATE accounts SET google_sub=$1,last_login=$2,failed_login_attempts=0,updated_at=NOW() WHERE id=$3',[identity.sub,new Date().toISOString(),a.id]);
        return a;
      });
      const old=parseCookies(req).edulink_session;if(old)sessions.delete(old);
      const session=random(),role=roleCode(account.role);
      sessions.set(session,{accountId:Number(account.id),email:account.email,role,...(flow.accountId?{googleLinkResult:'success'}:{})});
      const timer=setTimeout(()=>sessions.delete(session),28800000);timer.unref();
      redirect(role==='teacher'?'/teacher.html':role==='student'?'/student.html':'/',[cookie('',0),`edulink_session=${session}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${secure}`]);
    }catch{
      console.warn('Google authorization failed at stage:',errorCode);
      // Keep feedback in the authenticated session so cabinet redirects cannot hide it.
      const active=sessions?.get(parseCookies(req).edulink_session);
      if(active && (!linkSession || active===linkSession)){
        active.googleLinkResult=errorCode;
        redirect(active.role==='teacher'?'/teacher.html':active.role==='student'?'/student.html':'/',cookie('',0));
      }else redirect('/?google_error='+errorCode,cookie('',0));
    }
    return true;
  };
}
async function init(query){await query('ALTER TABLE accounts ADD COLUMN IF NOT EXISTS google_sub TEXT; CREATE UNIQUE INDEX IF NOT EXISTS accounts_google_sub_unique ON accounts(google_sub) WHERE google_sub IS NOT NULL');}
module.exports={create,init,verifyIdToken,validateLink};
