import '@/styles/normalize.css';
import '@/styles/globals.css';
import type { AppProps } from 'next/app';
import React from 'react';
import detectEthereumProvider from '@metamask/detect-provider';

export const AccountContext = React.createContext(null);

export default function App({ Component, pageProps }: AppProps) {
  let [account, setAccount] = React.useState();

  React.useEffect(() => {
    let fn = async () => {
      const provider = await detectEthereumProvider();

      if (provider !== window.ethereum) {
        console.error('Do you have multiple wallets installed?');
        return;
      }

      const ethereum = window.ethereum;
      const accounts = await ethereum.request({ method: 'eth_accounts' });
      handleAccountsChanged(accounts, setAccount);

      // ethereum
      //   .request({ method: 'eth_requestAccounts' })
      //   .then(handleAccountsChanged)
      //   .catch((err) => {
      //     if (err.code === 4001) {
      //       // EIP-1193 userRejectedRequest error
      //       // If this happens, the user rejected the connection request.
      //       console.log('Please connect to MetaMask.');
      //     } else {
      //       console.error(err);
      //     }
      //   });
    };

    fn().then((_res) => { });
  }, [setAccount]);

  return <Component {...pageProps} />
}

function handleAccountsChanged(accounts: any) {
  if (accounts.length === 0) {
    // MetaMask is locked or the user has not connected any accounts
    console.log('Please connect to MetaMask.');
  } else if (accounts[0] !== currentAccount) {
    currentAccount = accounts[0];
    // Do any other work!
  }
}
