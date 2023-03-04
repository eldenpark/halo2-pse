import React from 'react';

import styles from './Main.module.css'
import ProofSummaryList from '@/components/ProofSummaryList/ProofSummaryList';
import Left from './Left';

const Main = () => {
  return (
    <div className={styles.wrapper}>
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
