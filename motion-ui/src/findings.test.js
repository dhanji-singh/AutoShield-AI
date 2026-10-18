import test from 'node:test';
import assert from 'node:assert/strict';
import {groupFindings} from './findings.js';
test('repeated headers group without losing per-page evidence',()=>{
 const findings=[1,2].map(id=>({id,check:'hsts',title:'HSTS absent',severity:'low',verdict:'confirmed',evidence:{url:`https://example.com/${id}`}}));
 const original=JSON.stringify(findings),groups=groupFindings(findings);
 assert.equal(groups.length,1);assert.equal(groups[0].findings.length,2);
 assert.equal(JSON.stringify(findings),original);
});
test('different verdicts and non-header probes remain separate',()=>{
 const findings=[{check:'hsts',verdict:'confirmed'},{check:'hsts',verdict:'suspected'},{check:'sql_error'},{check:'sql_error'}];
 assert.equal(groupFindings(findings).length,4);
 assert.deepEqual(groupFindings([]),[]);
});
