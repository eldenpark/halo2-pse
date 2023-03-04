import React from 'react';
import styles from './ProofSummary.module.css'

const ProofSummary: React.FC<any> = () => {
  return (
    <div className={styles.wrapper}>
      <div>
        <p>Date</p>
        <p>2023 Jan 21</p>
      </div>
      <div>
        <p>Proof id</p>
        <p>01234</p>
      </div>
      <div>
        <p>Author</p>
        <p>Elden</p>
      </div>
      <div>
        <p>Description</p>
        <p>This proof verifies Elden has an Ether of amount somewhere between 0.26 to 0.28</p>
      </div>
      <div>
        <p>Proof algorithm</p>
        <p>Plonk - IPA </p>
      </div>
    </div>
  )
};

export default ProofSummary;
