import React from 'react';
import styles from './ProofSummary.module.css'

const ProofSummary: React.FC<any> = () => {
  return (
    <div className={styles.proofSummary}>
      <div className={styles.entry}>
        <p>Date</p>
        <p>2023 Jan 21</p>
      </div>
      <div className={styles.entry}>
        <p>Proof id</p>
        <p>01234</p>
      </div>
      <div className={styles.entry}>
        <p>Author</p>
        <p>Elden</p>
      </div>
      <div className={styles.entry}>
        <p>Description</p>
        <p>This proof verifies Elden has an Ether of amount somewhere between 0.26 to 0.28</p>
      </div>
      <div className={styles.entry}>
        <p>Proof algorithm</p>
        <p>Plonk - IPA </p>
      </div>
    </div>
  )
};

const ProofSummaryList = () => {
  let [list, setList] = React.useState<any>([]);

  React.useEffect(() => {
    setList([1, 2, 3]);
  }, []);

  let contents = list.map((elem: any) => {
    return (
      <ProofSummary>
        power
      </ProofSummary>
    )
  });

  return (
    <div className={styles.proofSummaryList}>
      <div className={styles.proofsLabel}>Proofs</div>
      <div>
        {contents}
      </div>
    </div>
  );
};

export default ProofSummaryList;
