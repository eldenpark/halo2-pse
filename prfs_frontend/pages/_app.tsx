import '@/styles/normalize.css';
import '@/styles/globals.css';
import type { AppProps } from 'next/app';
import React from 'react';
import detectEthereumProvider from '@metamask/detect-provider';
import { ethers } from 'ethers';
import { MetaMaskInpageProvider } from "@metamask/providers";

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

      const ethersProvider = new ethers.providers.Web3Provider(window.ethereum as any);
      window.ethers = ethersProvider;



      // const ethereum = window.ethereum;
      // ethereum.request({ method: 'eth_accounts' })
      //   .then((accounts) => handleAccountsChanged(accounts, account, setAccount))
      //   .catch((err) => {
      //     // Some unexpected error.
      //     // For backwards compatibility reasons, if no accounts are available,
      //     // eth_accounts will return an empty array.
      //     console.error(err);
      //   });

      // ethereum
      //   .request({ method: 'eth_requestAccounts' })
      //   .then((accounts) => handleAccountsChanged(accounts, account, setAccount))
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

function handleAccountsChanged(accounts: any, currAccount: any, setAccount: any) {
  if (accounts.length === 0) {
    // MetaMask is locked or the user has not connected any accounts
    console.log('Please connect to MetaMask.');
  } else if (accounts[0] !== currAccount) {
    console.log('new eth account is detected', accounts[0]);
    setAccount(accounts[0]);
  }
}

declare global {
  interface Window {
    ethereum: MetaMaskInpageProvider;
    ethers: ethers.providers.Web3Provider;
  }
}

