import test from 'node:test';
import assert from 'node:assert/strict';
import {api} from './api.js';
test('read saved scans uses same-origin API without a request body',async()=>{
 const original=global.fetch;global.fetch=async(url,opts)=>{assert.equal(url,'/api/scans');assert.equal(opts.method,'GET');assert.equal(opts.body,undefined);return {ok:true,json:async()=>({scans:[]})}};
 try{assert.deepEqual(await api('/scans'),{scans:[]})}finally{global.fetch=original}
});
test('start session preserves scope, limits and authorization acknowledgment',async()=>{
 const body={target:'http://proxy/',mode:'passive',max_requests:10,authorization_confirmed:true};const original=global.fetch;
 global.fetch=async(url,opts)=>{assert.equal(opts.method,'POST');assert.deepEqual(JSON.parse(opts.body),body);assert.equal(opts.headers['Content-Type'],'application/json');return {ok:true,json:async()=>({id:3})}};
 try{assert.equal((await api('/scans',body)).id,3)}finally{global.fetch=original}
});
test('backend authorization error is surfaced',async()=>{
 const original=global.fetch;global.fetch=async()=>({ok:false,json:async()=>({detail:'Confirm authorization'})});
 try{await assert.rejects(api('/scans',{}),/Confirm authorization/)}finally{global.fetch=original}
});
test('structured validation errors remain readable',async()=>{
 const original=global.fetch;global.fetch=async()=>({ok:false,json:async()=>({detail:[{msg:'Invalid scope'}]})});
 try{await assert.rejects(api('/scans',{}),/Invalid scope/)}finally{global.fetch=original}
});
