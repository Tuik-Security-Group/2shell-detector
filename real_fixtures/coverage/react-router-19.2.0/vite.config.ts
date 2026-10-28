import {unstable_reactRouterRSC} from '@react-router/dev/vite';
import rsc from '@vitejs/plugin-rsc';
import {defineConfig} from 'vite';
export default defineConfig({plugins:[unstable_reactRouterRSC(),rsc()]});
