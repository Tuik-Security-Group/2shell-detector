async function echo() { 'use server'; return 'local fixture'; }
export function ServerComponent() { return <main>Local React Router RSC fixture<form action={echo}><button>Local fixture</button></form></main>; }
