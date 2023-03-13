import '@/styles/normalize.css'
import '@/styles/globals.css'
import type { AppProps } from 'next/app'
import React from 'react';

import detectEthereumProvider from '@metamask/detect-provider';

export default function App({ Component, pageProps }: AppProps) {
  React.useEffect(() => {
    let fn = async () => {
      const provider = await detectEthereumProvider();
      console.log(11, provider); 
    };

  }, []);

  return <Component {...pageProps} />
}
