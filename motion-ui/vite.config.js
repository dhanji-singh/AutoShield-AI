import {defineConfig} from 'vite';
export default defineConfig({server:{host:'127.0.0.1',port:8502,strictPort:true,proxy:{
 '/api/mcp':{target:'http://127.0.0.1:8011',changeOrigin:false},
 '/api':{target:'http://127.0.0.1:8000',changeOrigin:false,rewrite:p=>p.replace(/^\/api/,'')}
}}});
