import { Form } from '../components/form';
async function echo() { 'use server'; return 'local fixture'; }
export default function Home() { return <main>Local Waku fixture<Form action={echo}/></main>; }
export const getConfig = () => ({render:'dynamic'});
