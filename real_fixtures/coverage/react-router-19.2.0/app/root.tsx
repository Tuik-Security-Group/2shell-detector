import {Outlet,Links,Meta,ScrollRestoration} from 'react-router';
export function Layout({children}) { return <html><head><Meta/><Links/></head><body>{children}<ScrollRestoration/></body></html>; }
export default function Root() { return <Outlet/>; }
