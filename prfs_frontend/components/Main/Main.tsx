import React from 'react';
import styles from './Main.module.css'

import ProofSummaryList from '@/components/ProofSummaryList/ProofSummaryList';
import Left from './Left';
// import Web3 from 'web3';

import { MetaMaskInpageProvider } from "@metamask/providers";

declare global {
  interface Window {
    ethereum?: MetaMaskInpageProvider
  }
}

// const web3: Web3 = new Web3(Web3.givenProvider || "ws://localhost:8545");
// export const Web3Context = React.createContext<Web3>(web3);

const Main = () => {
  // React.useEffect(() => {

  // }, []);

  return (
    <div className={styles.wrapper} >
      <div className={styles.inner}>
        <Left />
        <div className={styles.right}>
          <ProofSummaryList />
        </div>
      </div>
    </div >

  );
};

export default Main;
