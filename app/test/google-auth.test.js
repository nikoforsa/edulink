const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {verifyIdToken,create}=require('../google-auth');
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const key={...publicKey.export({format:'jwk'}),kid:'test'};
const claims=()=>({iss:'https://accounts.google.com',aud:'client',sub:'123',email:'user@gmail.com',email_verified:true,nonce:'nonce',iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+600});
function token(p){const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'test'})).toString('base64url'),b=Buffer.from(JSON.stringify(p)).toString('base64url');return h+'.'+b+'.'+crypto.sign('RSA-SHA256',Buffer.from(h+'.'+b),privateKey).toString('base64url');}
const verify=p=>verifyIdToken(token(p),'client','nonce',async()=>({keys:[key]}));
test('valid signed identity',async()=>assert.equal((await verify(claims())).sub,'123'));
for(const [field,value] of Object.entries({aud:'attacker',iss:'https://example.com',exp:0,nonce:'other',email_verified:false,sub:'',iat:9999999999,azp:'attacker'}))test('reject '+field,async()=>{await assert.rejects(verify({...claims(),[field]:value}));});
test('reject tampered signature',async()=>{const t=token(claims()).split('.');t[1]=Buffer.from(JSON.stringify({...claims(),sub:'attacker'})).toString('base64url');await assert.rejects(verifyIdToken(t.join('.'),'client','nonce',async()=>({keys:[key]})));});
test('reject callback without browser state before network or database',async()=>{
 const old={...process.env};process.env.GOOGLE_CLIENT_ID='test';process.env.GOOGLE_CLIENT_SECRET='secret';process.env.GOOGLE_REDIRECT_URI='https://example.com/api/auth/google/callback';
 try{const handler=create({parseCookies:()=>({}),transaction:()=>{throw Error('Unexpected database call');}});let headers;const res={writeHead:(s,h)=>{assert.equal(s,302);headers=h;},end:()=>{}};await handler({url:'/api/auth/google/callback?code=fake&state=fake',method:'GET'},res);assert.equal(headers.Location,'/?google_error=state');}finally{for(const k of ['GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET','GOOGLE_REDIRECT_URI'])if(old[k]===undefined)delete process.env[k];else process.env[k]=old[k];}
});

const {validateLink}=require('../google-auth');
const linkAccount={id:7,email:'person@example.org',password_hash:'hash',status:'Активен',email_verified:true,google_sub:null};
const linkFlow={accountId:7,sessionToken:'session',passwordHash:'hash'};
const linkIdentity={email:'person@example.org',sub:'google-id'};
const linkSessions=new Map([['session',{accountId:7}]]);
test('password-confirmed link accepts external email',()=>assert.doesNotThrow(()=>validateLink(linkAccount,linkIdentity,linkFlow,'session',linkSessions)));
for(const [name,account,identity,token,sessions] of [
 ['different email',linkAccount,{...linkIdentity,email:'attacker@example.org'},'session',linkSessions],
 ['different browser session',linkAccount,linkIdentity,'other',linkSessions],
 ['logged out',linkAccount,linkIdentity,'session',new Map()],
 ['password changed',{...linkAccount,password_hash:'new'},linkIdentity,'session',linkSessions],
 ['blocked',{...linkAccount,status:'Заблокирован'},linkIdentity,'session',linkSessions],
 ['existing other link',{...linkAccount,google_sub:'other'},linkIdentity,'session',linkSessions]
])test('link rejects '+name,()=>assert.throws(()=>validateLink(account,identity,linkFlow,token,sessions)));
