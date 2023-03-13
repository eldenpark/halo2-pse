import React from "react";
import styles from "./Main.module.scss";

import ProofSummaryList from "@/components/ProofSummaryList/ProofSummaryList";
import Left from "./Left";

import { MetaMaskInpageProvider } from "@metamask/providers";

declare global {
  interface Window {
    ethereum?: MetaMaskInpageProvider;
  }
}

const TopNav = () => {
  return (
    <div className={styles.topNav}>
      <div className={styles.content}>
        <div className={styles.logo}>Prfs</div>
        <ul>
          <li>Generate</li>
          <li>Browse</li>
          <li>Sign in</li>
        </ul>
      </div>
    </div>
  );
};

const Main = () => {
  return (
    <div className={styles.wrapper}>
      <TopNav />
      <div className={styles.content}>
        <Left className={styles.left} />
        <div className={styles.right}>
          <ProofSummaryList />
        </div>
      </div>
    </div>
  );
};

export default Main;
